"""Diagnostic engine.

Correlates Kubernetes, NetworkPolicy, OVN, OVS, and TCP connectivity
data to produce a comprehensive diagnosis.
"""

from __future__ import annotations

from typing import Any

from ovn_netdiag.config import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_LIKELY,
    CONFIDENCE_UNKNOWN,
    MODE_MOCK,
    RuntimeConfig,
    VERDICT_DENIED,
    VERDICT_FAILED,
    VERDICT_PASS,
    VERDICT_UNKNOWN,
)
from ovn_netdiag.connectivity import ConnectivityTester
from ovn_netdiag.kubernetes_inspector import KubernetesInspector, KubernetesSnapshot
from ovn_netdiag.logging_config import get_logger
from ovn_netdiag.models import (
    CheckResult,
    DiagnosticReport,
    OvnACL,
    OvnState,
    OvsFlow,
    OvsState,
    PodInfo,
)
from ovn_netdiag.ovn_inspector import OvnInspector
from ovn_netdiag.ovs_inspector import OvsInspector
from ovn_netdiag.policy_analyzer import PolicyAnalyzer, PolicyVerdict

logger = get_logger("diagnostic_engine")


class DiagnosticEngine:
    """Orchestrates the full diagnostic workflow.

    Args:
        config: Runtime configuration.
    """

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self.k8s = KubernetesInspector(config)
        self.ovn = OvnInspector(config)
        self.ovs = OvsInspector(config)
        self.connectivity = ConnectivityTester(config)
        self.policy_analyzer = PolicyAnalyzer()

    def diagnose(
        self,
        namespace: str,
        source: str,
        destination: str,
        port: int,
        protocol: str = "tcp",
    ) -> DiagnosticReport:
        """Run a full diagnostic for source -> destination on port/protocol.

        Args:
            namespace: Namespace of the source pod.
            source: Source pod name.
            destination: Destination pod name (searched across all namespaces
                in mock mode, or in the same namespace if no cross-namespace
                match is found).
            port: Destination port.
            protocol: Protocol (tcp/udp).

        Returns:
            A :class:`DiagnosticReport` with all checks and a final diagnosis.
        """
        report = DiagnosticReport(
            source_pod=f"{namespace}/{source}",
            destination_pod=destination,
            destination_ip="",
            port=port,
            protocol=protocol,
            mode=self.config.mode,
        )

        # 1. Collect Kubernetes resources
        snapshot = self.k8s.get_snapshot()

        # 2. Find source and destination pods
        source_pod = self._find_pod(snapshot, namespace, source)
        dest_pod = self._find_destination_pod(snapshot, namespace, destination)

        if not source_pod:
            report.add_check(CheckResult(
                name="KUBERNETES",
                verdict=VERDICT_FAILED,
                confidence=CONFIDENCE_CONFIRMED,
                details=f"Source pod {namespace}/{source} not found",
            ))
            report.diagnosis = f"Source pod {namespace}/{source} not found in the cluster."
            report.confidence = CONFIDENCE_CONFIRMED
            return report

        if not dest_pod:
            report.add_check(CheckResult(
                name="KUBERNETES",
                verdict=VERDICT_FAILED,
                confidence=CONFIDENCE_CONFIRMED,
                details=f"Destination pod {destination} not found",
            ))
            report.diagnosis = f"Destination pod {destination} not found in the cluster."
            report.confidence = CONFIDENCE_CONFIRMED
            return report

        report.destination_ip = dest_pod.ip
        report.destination_pod = f"{dest_pod.namespace}/{dest_pod.name}"

        # 3. Kubernetes check
        k8s_check = self._check_kubernetes(source_pod, dest_pod, snapshot)
        report.add_check(k8s_check)

        # 4. NetworkPolicy check
        policy_check = self._check_network_policy(source_pod, dest_pod, port, protocol, snapshot)
        report.add_check(policy_check)

        # 5. OVN check
        ovn_check = self._check_ovn(source_pod, dest_pod, port, protocol)
        report.add_check(ovn_check)

        # 6. OVS check
        ovs_check = self._check_ovs(dest_pod, port)
        report.add_check(ovs_check)

        # 7. Connectivity check
        conn_check = self._check_connectivity(source_pod, dest_pod, port, protocol)
        report.add_check(conn_check)

        # 8. Correlate and produce final diagnosis
        self._correlate(report)
        return report

    def cluster_info(self) -> dict[str, Any]:
        """Return cluster overview information."""
        snapshot = self.k8s.get_snapshot()
        ovn_state = self.ovn.get_state()
        ovs_state = self.ovs.get_state()

        return {
            "mode": self.config.mode,
            "nodes": [
                {"name": n.name, "pod_cidr": n.pod_cidr, "status": n.status}
                for n in snapshot.nodes
            ],
            "pod_count": len(snapshot.pods),
            "service_count": len(snapshot.services),
            "network_policy_count": len(snapshot.network_policies),
            "ovn_logical_switches": len(ovn_state.logical_switches),
            "ovn_logical_routers": len(ovn_state.logical_routers),
            "ovn_port_groups": len(ovn_state.port_groups),
            "ovn_acls": len(ovn_state.acls),
            "ovs_bridges": [b.name for b in ovs_state.bridges],
            "ovs_flow_count": len(ovs_state.flows),
            "k8s_errors": snapshot.errors,
        }

    def pod_info(self, namespace: str, pod_name: str) -> dict[str, Any]:
        """Return detailed information about a specific pod."""
        pod = self.k8s.get_pod(namespace, pod_name)
        if not pod:
            return {
                "mode": self.config.mode,
                "error": f"Pod {namespace}/{pod_name} not found",
            }

        # Find related services
        snapshot = self.k8s.get_snapshot(namespace)
        related_services = []
        for svc in snapshot.services:
            if pod.matches_selector(svc.selector):
                related_services.append({
                    "name": svc.name,
                    "cluster_ip": svc.cluster_ip,
                    "type": svc.type,
                    "ports": [{"port": sp.port, "target_port": sp.target_port, "protocol": sp.protocol} for sp in svc.ports],
                })

        # Find related endpoints
        related_endpoints = []
        for ep in snapshot.endpoints:
            if pod.ip in ep.addresses:
                related_endpoints.append({
                    "name": ep.name,
                    "addresses": list(ep.addresses),
                    "ready": ep.ready,
                })

        # Find applicable NetworkPolicies
        all_policies = self.k8s.get_network_policies()
        applicable_policies = []
        for pol in all_policies:
            if pol.namespace == namespace and pod.matches_selector(pol.pod_selector):
                applicable_policies.append({
                    "name": pol.name,
                    "types": list(pol.types),
                    "pod_selector": pol.pod_selector,
                    "is_default_deny_ingress": pol.is_default_deny_ingress,
                    "is_default_deny_egress": pol.is_default_deny_egress,
                })

        # OVN port info
        ovn_state = self.ovn.get_state()
        ovn_port = None
        for lsp in ovn_state.logical_switch_ports:
            if pod.ip in lsp.addresses:
                ovn_port = {"name": lsp.name, "switch": lsp.switch, "addresses": list(lsp.addresses)}
                break

        return {
            "mode": self.config.mode,
            "pod": {
                "name": pod.name,
                "namespace": pod.namespace,
                "ip": pod.ip,
                "node": pod.node,
                "labels": pod.labels,
                "phase": pod.phase,
                "containers": [
                    {
                        "name": c.name,
                        "ports": [{"port": cp.container_port, "protocol": cp.protocol} for cp in c.ports],
                    }
                    for c in pod.containers
                ],
            },
            "related_services": related_services,
            "related_endpoints": related_endpoints,
            "applicable_network_policies": applicable_policies,
            "ovn_port": ovn_port,
        }

    def ovn_info(self) -> dict[str, Any]:
        """Return OVN state overview."""
        state = self.ovn.get_state()
        return {
            "mode": self.config.mode,
            "logical_switches": [
                {"name": ls.name, "subnet": ls.subnet} for ls in state.logical_switches
            ],
            "logical_switch_ports": [
                {"name": lsp.name, "switch": lsp.switch, "addresses": list(lsp.addresses), "type": lsp.type}
                for lsp in state.logical_switch_ports
            ],
            "port_groups": [
                {"name": pg.name, "ports": list(pg.ports)} for pg in state.port_groups
            ],
            "acls": [
                {
                    "uuid": a.uuid,
                    "port_group": a.port_group,
                    "direction": a.direction,
                    "priority": a.priority,
                    "match": a.match,
                    "action": a.action,
                    "log": a.log,
                }
                for a in state.acls
            ],
            "logical_routers": [
                {"name": lr.name, "ports": list(lr.ports)} for lr in state.logical_routers
            ],
            "logical_flows": [
                {"uuid": lf.uuid, "router": lf.router, "match": lf.match, "actions": lf.actions, "priority": lf.priority}
                for lf in state.logical_flows
            ],
        }

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_kubernetes(
        self,
        source_pod: PodInfo,
        dest_pod: PodInfo,
        snapshot: KubernetesSnapshot,
    ) -> CheckResult:
        """Check that both pods are running and have valid IPs."""
        evidence: list[str] = []
        problems: list[str] = []

        if source_pod.phase != "Running":
            problems.append(f"Source pod is in {source_pod.phase} phase")
        if dest_pod.phase != "Running":
            problems.append(f"Destination pod is in {dest_pod.phase} phase")
        if not source_pod.ip:
            problems.append("Source pod has no IP address")
        if not dest_pod.ip:
            problems.append("Destination pod has no IP address")

        evidence.append(f"Source: {source_pod.namespace}/{source_pod.name} ip={source_pod.ip} node={source_pod.node}")
        evidence.append(f"Destination: {dest_pod.namespace}/{dest_pod.name} ip={dest_pod.ip} node={dest_pod.node}")

        if problems:
            return CheckResult(
                name="KUBERNETES",
                verdict=VERDICT_FAILED,
                confidence=CONFIDENCE_CONFIRMED,
                details="; ".join(problems),
                evidence=evidence,
            )
        return CheckResult(
            name="KUBERNETES",
            verdict=VERDICT_PASS,
            confidence=CONFIDENCE_CONFIRMED,
            details="Both pods are Running with valid IPs",
            evidence=evidence,
        )

    def _check_network_policy(
        self,
        source_pod: PodInfo,
        dest_pod: PodInfo,
        port: int,
        protocol: str,
        snapshot: KubernetesSnapshot,
    ) -> CheckResult:
        """Analyze NetworkPolicies for the traffic path."""
        all_namespaces = {p.namespace for p in snapshot.pods}
        verdict: PolicyVerdict = self.policy_analyzer.analyze(
            source_pod=source_pod,
            dest_pod=dest_pod,
            port=port,
            protocol=protocol,
            policies=snapshot.network_policies,
            all_pods=snapshot.pods,
            all_namespaces=all_namespaces,
        )

        if verdict.verdict == "ALLOWED":
            v = VERDICT_PASS
        elif verdict.verdict == "DENIED":
            v = VERDICT_DENIED
        else:
            v = VERDICT_UNKNOWN

        return CheckResult(
            name="NETWORK POLICY",
            verdict=v,
            confidence=verdict.confidence,
            details=verdict.reason,
            evidence=verdict.evidence,
            data={
                "matching_policies": verdict.matching_policies,
                "denying_policies": verdict.denying_policies,
            },
        )

    def _check_ovn(
        self,
        source_pod: PodInfo,
        dest_pod: PodInfo,
        port: int,
        protocol: str,
    ) -> CheckResult:
        """Inspect OVN ACLs for the traffic path."""
        state: OvnState = self.ovn.get_state()
        evidence: list[str] = []

        # Find the logical switch port for the destination
        dest_lsp = self.ovn.find_lsp_by_ip(dest_pod.ip)
        source_lsp = self.ovn.find_lsp_by_ip(source_pod.ip)

        if not dest_lsp:
            evidence.append(f"No OVN logical switch port found for destination IP {dest_pod.ip}")
            return CheckResult(
                name="OVN ACL",
                verdict=VERDICT_UNKNOWN,
                confidence=CONFIDENCE_LIKELY,
                details="Destination pod not found in OVN",
                evidence=evidence,
            )

        evidence.append(f"Destination LSP: {dest_lsp}")
        if source_lsp:
            evidence.append(f"Source LSP: {source_lsp}")

        # Find ACLs on the port group that contains the destination LSP
        relevant_acls: list[OvnACL] = []
        for pg in state.port_groups:
            if dest_lsp in pg.ports:
                for acl in state.acls:
                    if acl.port_group == pg.name:
                        relevant_acls.append(acl)
                        evidence.append(
                            f"ACL on {pg.name}: priority={acl.priority} direction={acl.direction} "
                            f"match='{acl.match}' action={acl.action}"
                        )

        if not relevant_acls:
            evidence.append("No ACLs found on destination port group")
            return CheckResult(
                name="OVN ACL",
                verdict=VERDICT_PASS,
                confidence=CONFIDENCE_LIKELY,
                details="No OVN ACLs restrict the destination port",
                evidence=evidence,
            )

        # Check for allow vs drop
        has_allow = False
        has_drop = False
        drop_acls: list[str] = []
        allow_acls: list[str] = []

        # Build IP-based match string for checking
        src_ip = source_pod.ip
        dst_port_str = str(port)

        for acl in relevant_acls:
            match_lower = acl.match.lower()
            # Check if this ACL is relevant to our traffic
            is_relevant = False
            if "ip" == match_lower or match_lower == "ip4" or match_lower == "ip6":
                is_relevant = True
            elif src_ip in match_lower and dst_port_str in match_lower:
                is_relevant = True
            elif src_ip in match_lower and "tcp" in match_lower:
                # May match on protocol but not specific port
                is_relevant = True

            if not is_relevant:
                continue

            if acl.action in ("allow", "allow-related"):
                has_allow = True
                allow_acls.append(acl.uuid)
            elif acl.action in ("drop", "reject"):
                has_drop = True
                drop_acls.append(acl.uuid)

        if has_allow and not has_drop:
            return CheckResult(
                name="OVN ACL",
                verdict=VERDICT_PASS,
                confidence=CONFIDENCE_CONFIRMED,
                details="OVN ACLs allow the traffic",
                evidence=evidence,
            )
        if has_drop and not has_allow:
            return CheckResult(
                name="OVN ACL",
                verdict=VERDICT_DENIED,
                confidence=CONFIDENCE_CONFIRMED,
                details="OVN ACLs drop the traffic",
                evidence=evidence,
            )
        if has_drop and has_allow:
            # Higher priority wins in OVN; allow-related typically has higher priority
            allow_pri = max(
                (a.priority for a in relevant_acls if a.action in ("allow", "allow-related") and a.uuid in allow_acls),
                default=0,
            )
            drop_pri = max(
                (a.priority for a in relevant_acls if a.action in ("drop", "reject") and a.uuid in drop_acls),
                default=0,
            )
            if allow_pri > drop_pri:
                return CheckResult(
                    name="OVN ACL",
                    verdict=VERDICT_PASS,
                    confidence=CONFIDENCE_LIKELY,
                    details=f"Allow ACL (priority {allow_pri}) overrides drop ACL (priority {drop_pri})",
                    evidence=evidence,
                )
            return CheckResult(
                name="OVN ACL",
                verdict=VERDICT_DENIED,
                confidence=CONFIDENCE_LIKELY,
                details=f"Drop ACL (priority {drop_pri}) overrides allow ACL (priority {allow_pri})",
                evidence=evidence,
            )

        return CheckResult(
            name="OVN ACL",
            verdict=VERDICT_UNKNOWN,
            confidence=CONFIDENCE_UNKNOWN,
            details="OVN ACLs exist but relevance to this traffic is uncertain",
            evidence=evidence,
        )

    def _check_ovs(self, dest_pod: PodInfo, port: int) -> CheckResult:
        """Inspect OVS flows for the destination."""
        state: OvsState = self.ovs.get_state()
        evidence: list[str] = []

        relevant_flows: list[OvsFlow] = []
        for flow in state.flows:
            match_lower = flow.match.lower()
            if dest_pod.ip.lower() in match_lower:
                relevant_flows.append(flow)
                evidence.append(
                    f"Flow: priority={flow.priority} table={flow.table} match='{flow.match}' actions={flow.actions}"
                )

        if not relevant_flows:
            evidence.append(f"No OVS flows found matching destination IP {dest_pod.ip}")
            return CheckResult(
                name="OVS FLOW",
                verdict=VERDICT_UNKNOWN,
                confidence=CONFIDENCE_LIKELY,
                details="No matching OVS flows found",
                evidence=evidence,
            )

        has_output = any(not f.is_drop for f in relevant_flows)
        has_drop = any(f.is_drop for f in relevant_flows)

        if has_output and not has_drop:
            return CheckResult(
                name="OVS FLOW",
                verdict=VERDICT_PASS,
                confidence=CONFIDENCE_LIKELY,
                details="OVS flows forward traffic to destination",
                evidence=evidence,
            )
        if has_drop and not has_output:
            return CheckResult(
                name="OVS FLOW",
                verdict=VERDICT_DENIED,
                confidence=CONFIDENCE_LIKELY,
                details="OVS flows drop traffic to destination",
                evidence=evidence,
            )
        if has_drop and has_output:
            # Highest priority wins
            output_pri = max((f.priority for f in relevant_flows if not f.is_drop), default=0)
            drop_pri = max((f.priority for f in relevant_flows if f.is_drop), default=0)
            if output_pri >= drop_pri:
                return CheckResult(
                    name="OVS FLOW",
                    verdict=VERDICT_PASS,
                    confidence=CONFIDENCE_LIKELY,
                    details=f"Output flow (priority {output_pri}) >= drop flow (priority {drop_pri})",
                    evidence=evidence,
                )
            return CheckResult(
                name="OVS FLOW",
                verdict=VERDICT_DENIED,
                confidence=CONFIDENCE_LIKELY,
                details=f"Drop flow (priority {drop_pri}) > output flow (priority {output_pri})",
                evidence=evidence,
            )

        return CheckResult(
            name="OVS FLOW",
            verdict=VERDICT_UNKNOWN,
            confidence=CONFIDENCE_UNKNOWN,
            details="OVS flow analysis inconclusive",
            evidence=evidence,
        )

    def _check_connectivity(
        self,
        source_pod: PodInfo,
        dest_pod: PodInfo,
        port: int,
        protocol: str,
    ) -> CheckResult:
        """Run TCP connectivity test."""
        source_str = f"{source_pod.namespace}/{source_pod.name}"
        target_str = f"{dest_pod.namespace}/{dest_pod.name}"
        result = self.connectivity.test(
            source=source_str,
            target=target_str,
            destination_ip=dest_pod.ip,
            port=port,
            protocol=protocol,
        )

        evidence = [
            f"source={result.source} target={result.target}",
            f"destination_ip={result.destination_ip} port={result.port} protocol={result.protocol}",
            f"reachable={result.reachable} latency_ms={result.latency_ms}",
        ]
        if result.error:
            evidence.append(f"error={result.error}")

        verdict = VERDICT_PASS if result.reachable else VERDICT_FAILED
        details = (
            f"Connection {'succeeded' if result.reachable else 'failed'}"
            + (f" in {result.latency_ms}ms" if result.latency_ms is not None else "")
            + (f" — {result.error}" if result.error else "")
        )

        return CheckResult(
            name="TCP CONNECTIVITY",
            verdict=verdict,
            confidence=CONFIDENCE_CONFIRMED,
            details=details,
            evidence=evidence,
            data={
                "reachable": result.reachable,
                "latency_ms": result.latency_ms,
                "error": result.error,
            },
        )

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def _correlate(self, report: DiagnosticReport) -> None:
        """Correlate all check results into a final diagnosis."""
        checks_by_name = {c.name: c for c in report.checks}

        k8s = checks_by_name.get("KUBERNETES")
        policy = checks_by_name.get("NETWORK POLICY")
        ovn = checks_by_name.get("OVN ACL")
        ovs = checks_by_name.get("OVS FLOW")
        conn = checks_by_name.get("TCP CONNECTIVITY")

        # If Kubernetes check failed, that's the primary issue
        if k8s and k8s.verdict == VERDICT_FAILED:
            report.diagnosis = k8s.details
            report.confidence = CONFIDENCE_CONFIRMED
            return

        # Gather verdicts
        policy_denied = policy is not None and policy.verdict == VERDICT_DENIED
        ovn_denied = ovn is not None and ovn.verdict == VERDICT_DENIED
        ovs_denied = ovs is not None and ovs.verdict == VERDICT_DENIED
        conn_failed = conn is not None and conn.verdict == VERDICT_FAILED

        policy_allowed = policy is not None and policy.verdict == VERDICT_PASS
        ovn_allowed = ovn is not None and ovn.verdict == VERDICT_PASS
        conn_ok = conn is not None and conn.verdict == VERDICT_PASS

        # Case 1: Connectivity OK and everything allows
        if conn_ok and policy_allowed and ovn_allowed:
            report.diagnosis = "Traffic is reachable and allowed by all layers (Kubernetes, NetworkPolicy, OVN, OVS)."
            report.confidence = CONFIDENCE_CONFIRMED
            return

        # Case 2: Connectivity failed and NetworkPolicy denies
        if conn_failed and policy_denied:
            report.diagnosis = "NetworkPolicy appears to block traffic."
            report.confidence = CONFIDENCE_CONFIRMED
            if ovn_denied:
                report.diagnosis += " OVN ACLs also show a drop action, corroborating the NetworkPolicy denial."
            return

        # Case 3: Connectivity failed and OVN denies (but policy allows)
        if conn_failed and ovn_denied and policy_allowed:
            report.diagnosis = "OVN ACLs appear to block traffic despite NetworkPolicy allowing it."
            report.confidence = CONFIDENCE_CONFIRMED
            return

        # Case 4: Connectivity failed and OVS denies
        if conn_failed and ovs_denied and policy_allowed and ovn_allowed:
            report.diagnosis = "OVS flows appear to drop traffic despite NetworkPolicy and OVN allowing it."
            report.confidence = CONFIDENCE_LIKELY
            return

        # Case 5: Connectivity OK but policy denies
        if conn_ok and policy_denied:
            report.diagnosis = "Traffic is reachable but NetworkPolicy analysis suggests it should be blocked. This may indicate a policy misconfiguration or that the policy is not enforced."
            report.confidence = CONFIDENCE_LIKELY
            return

        # Case 6: Connectivity OK, policy allows, OVN unknown
        if conn_ok and policy_allowed:
            report.diagnosis = "Traffic is reachable and NetworkPolicy allows it. OVN/OVS state could not be fully verified."
            report.confidence = CONFIDENCE_LIKELY
            return

        # Case 7: Connectivity failed but all layers allow
        if conn_failed and policy_allowed and ovn_allowed:
            report.diagnosis = "Traffic is unreachable despite NetworkPolicy and OVN allowing it. The issue may be at the application level, node networking, or OVS flow configuration."
            report.confidence = CONFIDENCE_LIKELY
            return

        # Case 8: Connectivity failed, everything unknown
        if conn_failed:
            reasons: list[str] = []
            if policy:
                reasons.append(f"NetworkPolicy: {policy.verdict}")
            if ovn:
                reasons.append(f"OVN: {ovn.verdict}")
            if ovs:
                reasons.append(f"OVS: {ovs.verdict}")
            report.diagnosis = f"Traffic is unreachable. Layer verdicts: {', '.join(reasons)}. Root cause is uncertain."
            report.confidence = CONFIDENCE_UNKNOWN
            return

        # Fallback
        verdicts = [c.verdict for c in report.checks]
        report.diagnosis = f"Diagnostic inconclusive. Check verdicts: {', '.join(verdicts)}."
        report.confidence = CONFIDENCE_UNKNOWN

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_pod(self, snapshot: KubernetesSnapshot, namespace: str, name: str) -> PodInfo | None:
        """Find a pod by namespace and name."""
        for pod in snapshot.pods:
            if pod.namespace == namespace and pod.name == name:
                return pod
        return None

    def _find_destination_pod(self, snapshot: KubernetesSnapshot, namespace: str, name: str) -> PodInfo | None:
        """Find the destination pod.

        First searches in the given namespace, then across all namespaces.
        """
        # Search in the given namespace first
        pod = self._find_pod(snapshot, namespace, name)
        if pod:
            return pod
        # Search across all namespaces
        for p in snapshot.pods:
            if p.name == name:
                return p
        return None
