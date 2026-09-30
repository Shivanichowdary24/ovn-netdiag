"""NetworkPolicy analyzer.

Analyzes Kubernetes NetworkPolicies to determine whether traffic from a
source pod to a destination pod on a given port/protocol is allowed,
denied, or uncertain.

Key design:
- If no NetworkPolicies select a pod, all traffic is allowed (default allow).
- If any policy selects the pod for Ingress, only matching rules allow traffic.
- If any policy selects the pod for Egress, only matching rules allow traffic.
- Confidence levels: CONFIRMED (policy explicitly allows/denies), LIKELY
  (analysis suggests allow/deny but edge cases exist), UNKNOWN (insufficient
  data).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ovn_netdiag.config import CONFIDENCE_CONFIRMED, CONFIDENCE_LIKELY, CONFIDENCE_UNKNOWN
from ovn_netdiag.logging_config import get_logger
from ovn_netdiag.models import (
    NetworkPolicyInfo,
    NetworkPolicyPort,
    NetworkPolicyRule,
    PodInfo,
)

logger = get_logger("policy_analyzer")


@dataclass
class PolicyVerdict:
    """Result of NetworkPolicy analysis."""

    allowed: bool
    confidence: str  # CONFIRMED | LIKELY | UNKNOWN
    reason: str
    matching_policies: list[str] = field(default_factory=list)
    denying_policies: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """Return a human-readable verdict string."""
        if self.confidence == CONFIDENCE_UNKNOWN:
            return "UNKNOWN"
        return "ALLOWED" if self.allowed else "DENIED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "confidence": self.confidence,
            "reason": self.reason,
            "matching_policies": self.matching_policies,
            "denying_policies": self.denying_policies,
            "evidence": self.evidence,
        }


class PolicyAnalyzer:
    """Analyze NetworkPolicies for traffic between two pods."""

    def analyze(
        self,
        source_pod: PodInfo,
        dest_pod: PodInfo,
        port: int,
        protocol: str,
        policies: list[NetworkPolicyInfo],
        all_pods: list[PodInfo] | None = None,
        all_namespaces: set[str] | None = None,
    ) -> PolicyVerdict:
        """Analyze whether *source_pod* can reach *dest_pod* on *port*/*protocol*.

        Args:
            source_pod: The source pod.
            dest_pod: The destination pod.
            port: Destination port.
            protocol: Protocol (TCP/UDP).
            policies: All NetworkPolicies in the cluster (or relevant namespaces).
            all_pods: All pods (used for podSelector matching across namespaces).
            all_namespaces: Set of namespace names (used for namespaceSelector).

        Returns:
            PolicyVerdict with allow/deny determination and confidence.
        """
        proto = protocol.upper()
        all_pods = all_pods or []
        all_namespaces = all_namespaces or set()

        # 1. Check ingress policies on the destination pod
        ingress_result = self._analyze_ingress(
            source_pod, dest_pod, port, proto, policies, all_pods, all_namespaces,
        )

        # 2. Check egress policies on the source pod
        egress_result = self._analyze_egress(
            source_pod, dest_pod, port, proto, policies, all_pods, all_namespaces,
        )

        # 3. Combine: traffic is allowed only if both ingress and egress allow
        if not ingress_result["allowed"] or not egress_result["allowed"]:
            denying = ingress_result["denying_policies"] + egress_result["denying_policies"]
            evidence = ingress_result["evidence"] + egress_result["evidence"]
            reason = ingress_result["reason"] if not ingress_result["allowed"] else egress_result["reason"]
            confidence = CONFIDENCE_CONFIRMED if denying else CONFIDENCE_LIKELY
            return PolicyVerdict(
                allowed=False,
                confidence=confidence,
                reason=reason,
                matching_policies=ingress_result["matching_policies"] + egress_result["matching_policies"],
                denying_policies=denying,
                evidence=evidence,
            )

        # Both ingress and egress allow
        evidence = ingress_result["evidence"] + egress_result["evidence"]
        matching = ingress_result["matching_policies"] + egress_result["matching_policies"]
        if matching:
            return PolicyVerdict(
                allowed=True,
                confidence=CONFIDENCE_CONFIRMED,
                reason="Traffic is explicitly allowed by NetworkPolicy rules",
                matching_policies=matching,
                evidence=evidence,
            )
        # No policies select either pod — default allow
        return PolicyVerdict(
            allowed=True,
            confidence=CONFIDENCE_CONFIRMED,
            reason="No NetworkPolicies select the source or destination pod; default allow applies",
            evidence=["No matching NetworkPolicies found for source or destination"],
        )

    # ------------------------------------------------------------------
    # Ingress analysis
    # ------------------------------------------------------------------

    def _analyze_ingress(
        self,
        source_pod: PodInfo,
        dest_pod: PodInfo,
        port: int,
        proto: str,
        policies: list[NetworkPolicyInfo],
        all_pods: list[PodInfo],
        all_namespaces: set[str],
    ) -> dict[str, Any]:
        """Analyze ingress policies on the destination pod."""
        selecting_policies = [
            p for p in policies
            if p.namespace == dest_pod.namespace and p.has_ingress and dest_pod.matches_selector(p.pod_selector)
        ]

        if not selecting_policies:
            return {
                "allowed": True,
                "confidence": CONFIDENCE_CONFIRMED,
                "reason": "",
                "matching_policies": [],
                "denying_policies": [],
                "evidence": [f"No ingress NetworkPolicies select {dest_pod.namespace}/{dest_pod.name}"],
            }

        # If any selecting policy has rules, check if any rule allows the traffic
        has_any_rules = any(p.ingress_rules for p in selecting_policies if p.ingress_rules)
        if not has_any_rules:
            # All selecting policies are default-deny with no allow rules
            denying = [p.name for p in selecting_policies if p.is_default_deny_ingress]
            return {
                "allowed": False,
                "confidence": CONFIDENCE_CONFIRMED,
                "reason": f"Ingress denied by default-deny policies on {dest_pod.namespace}/{dest_pod.name}: {', '.join(denying)}",
                "matching_policies": [],
                "denying_policies": denying,
                "evidence": [f"Default-deny ingress: {p.name}" for p in selecting_policies if p.is_default_deny_ingress],
            }

        # Check each policy's rules
        for policy in selecting_policies:
            if not policy.ingress_rules:
                continue
            for rule in policy.ingress_rules:
                if self._rule_allows(source_pod, dest_pod, port, proto, rule, all_pods, all_namespaces):
                    return {
                        "allowed": True,
                        "confidence": CONFIDENCE_CONFIRMED,
                        "reason": f"Ingress allowed by policy {policy.name} in {dest_pod.namespace}",
                        "matching_policies": [policy.name],
                        "denying_policies": [],
                        "evidence": [
                            f"Policy {policy.name} rule matches: pod_selector={rule.pod_selector}, "
                            f"namespace_selector={rule.namespace_selector}, ports={[(p.port, p.protocol) for p in rule.ports]}",
                        ],
                    }

        # Rules exist but none match
        denying = [p.name for p in selecting_policies if p.ingress_rules]
        return {
            "allowed": False,
            "confidence": CONFIDENCE_CONFIRMED,
            "reason": f"Ingress denied: no matching ingress rules in policies on {dest_pod.namespace}/{dest_pod.name}",
            "matching_policies": [],
            "denying_policies": denying,
            "evidence": [f"No matching ingress rule in {p.name}" for p in selecting_policies if p.ingress_rules],
        }

    # ------------------------------------------------------------------
    # Egress analysis
    # ------------------------------------------------------------------

    def _analyze_egress(
        self,
        source_pod: PodInfo,
        dest_pod: PodInfo,
        port: int,
        proto: str,
        policies: list[NetworkPolicyInfo],
        all_pods: list[PodInfo],
        all_namespaces: set[str],
    ) -> dict[str, Any]:
        """Analyze egress policies on the source pod."""
        selecting_policies = [
            p for p in policies
            if p.namespace == source_pod.namespace and p.has_egress and source_pod.matches_selector(p.pod_selector)
        ]

        if not selecting_policies:
            return {
                "allowed": True,
                "confidence": CONFIDENCE_CONFIRMED,
                "reason": "",
                "matching_policies": [],
                "denying_policies": [],
                "evidence": [f"No egress NetworkPolicies select {source_pod.namespace}/{source_pod.name}"],
            }

        has_any_rules = any(p.egress_rules for p in selecting_policies if p.egress_rules)
        if not has_any_rules:
            denying = [p.name for p in selecting_policies if p.is_default_deny_egress]
            return {
                "allowed": False,
                "confidence": CONFIDENCE_CONFIRMED,
                "reason": f"Egress denied by default-deny policies on {source_pod.namespace}/{source_pod.name}: {', '.join(denying)}",
                "matching_policies": [],
                "denying_policies": denying,
                "evidence": [f"Default-deny egress: {p.name}" for p in selecting_policies if p.is_default_deny_egress],
            }

        for policy in selecting_policies:
            if not policy.egress_rules:
                continue
            for rule in policy.egress_rules:
                if self._rule_allows(dest_pod, source_pod, port, proto, rule, all_pods, all_namespaces):
                    return {
                        "allowed": True,
                        "confidence": CONFIDENCE_CONFIRMED,
                        "reason": f"Egress allowed by policy {policy.name} in {source_pod.namespace}",
                        "matching_policies": [policy.name],
                        "denying_policies": [],
                        "evidence": [
                            f"Policy {policy.name} egress rule matches destination {dest_pod.namespace}/{dest_pod.name}",
                        ],
                    }

        denying = [p.name for p in selecting_policies if p.egress_rules]
        return {
            "allowed": False,
            "confidence": CONFIDENCE_CONFIRMED,
            "reason": f"Egress denied: no matching egress rules in policies on {source_pod.namespace}/{source_pod.name}",
            "matching_policies": [],
            "denying_policies": denying,
            "evidence": [f"No matching egress rule in {p.name}" for p in selecting_policies if p.egress_rules],
        }

    # ------------------------------------------------------------------
    # Rule matching
    # ------------------------------------------------------------------

    def _rule_allows(
        self,
        peer_pod: PodInfo,
        protected_pod: PodInfo,
        port: int,
        proto: str,
        rule: NetworkPolicyRule,
        all_pods: list[PodInfo],
        all_namespaces: set[str],
    ) -> bool:
        """Check whether *rule* allows traffic from/to *peer_pod* on *port*/*proto*.

        For ingress: *peer_pod* is the source, *protected_pod* is the destination.
        For egress: *peer_pod* is the destination, *protected_pod* is the source.
        """
        # Check port match
        if not _port_matches(rule.ports, port, proto):
            return False

        # Check podSelector + namespaceSelector
        if rule.allows_all_pods:
            return True

        # Check ipBlock
        if rule.ip_blocks:
            for ip_block in rule.ip_blocks:
                if _ip_in_block(peer_pod.ip, ip_block):
                    return True

        # Check podSelector
        if rule.pod_selector:
            if rule.namespace_selector:
                # Both selectors: peer pod must match pod_selector AND be in a namespace
                # matching namespace_selector
                ns_match = _namespace_matches(rule.namespace_selector, peer_pod.namespace, all_namespaces)
                pod_match = peer_pod.matches_selector(rule.pod_selector)
                if ns_match and pod_match:
                    return True
            else:
                # podSelector only: peer pod must be in the same namespace as the policy
                # and match the selector
                if peer_pod.namespace == protected_pod.namespace and peer_pod.matches_selector(rule.pod_selector):
                    return True
                # Also check all pods in all namespaces
                for pod in all_pods:
                    if pod.matches_selector(rule.pod_selector):
                        if peer_pod.namespace == pod.namespace and pod.name == peer_pod.name:
                            return True

        elif rule.namespace_selector:
            # namespaceSelector only: all pods in matching namespaces
            if _namespace_matches(rule.namespace_selector, peer_pod.namespace, all_namespaces):
                return True

        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _port_matches(ports: tuple[NetworkPolicyPort, ...], port: int, proto: str) -> bool:
    """Check whether *port*/*proto* matches any of the rule's port restrictions."""
    if len(ports) == 0:
        return True  # No port restriction = all ports
    for p in ports:
        if p.protocol.upper() == proto:
            if p.port is None or p.port == port:
                return True
    return False


def _namespace_matches(
    selector: dict[str, str],
    namespace: str,
    all_namespaces: set[str],
) -> bool:
    """Check whether *namespace* matches the namespaceSelector."""
    if not selector:
        return True  # Empty selector matches all namespaces
    # In real Kubernetes, namespaceSelector uses label selectors.
    # Here we check "name" label as a simple convention.
    for key, value in selector.items():
        if key == "name":
            if namespace == value:
                return True
            else:
                return False
    return False


def _ip_in_block(ip: str, ip_block: str) -> bool:
    """Check whether *ip* is within *ip_block* (CIDR notation).

    Handles simple CIDR matching without external dependencies.
    """
    import ipaddress

    try:
        network = ipaddress.ip_network(ip_block, strict=False)
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False
