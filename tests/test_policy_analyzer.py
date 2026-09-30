"""Tests for the NetworkPolicy analyzer."""

from __future__ import annotations

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.kubernetes_inspector import KubernetesInspector
from ovn_netdiag.models import (
    NetworkPolicyInfo,
    NetworkPolicyPort,
    NetworkPolicyRule,
    PodInfo,
    Container,
    ContainerPort,
)
from ovn_netdiag.policy_analyzer import PolicyAnalyzer, PolicyVerdict


def _make_pod(name: str, namespace: str, ip: str, labels: dict[str, str]) -> PodInfo:
    return PodInfo(
        name=name,
        namespace=namespace,
        ip=ip,
        node="node-1",
        labels=labels,
        containers=(Container(name="c", ports=(ContainerPort(8080),),),),
    )


class TestPolicyAnalyzer:
    """Test the NetworkPolicy analysis logic."""

    def test_no_policies_default_allow(self) -> None:
        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "ns1", "10.0.0.1", {"app": "src"})
        dest = _make_pod("dst", "ns2", "10.0.0.2", {"app": "dst"})
        verdict = analyzer.analyze(source, dest, 8080, "tcp", [], [], set())
        assert verdict.allowed is True
        assert verdict.confidence == "CONFIRMED"

    def test_default_deny_ingress_blocks(self) -> None:
        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "frontend", "10.0.0.1", {"app": "frontend"})
        dest = _make_pod("dst", "backend", "10.0.0.2", {"app": "backend"})
        policy = NetworkPolicyInfo(
            name="deny-all",
            namespace="backend",
            types=("Ingress",),
            pod_selector={},
            ingress_rules=(),
            egress_rules=None,
        )
        verdict = analyzer.analyze(source, dest, 8080, "tcp", [policy], [source, dest], {"frontend", "backend"})
        assert verdict.allowed is False
        assert verdict.confidence == "CONFIRMED"
        assert "deny-all" in verdict.denying_policies

    def test_ingress_rule_allows_matching_traffic(self) -> None:
        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "frontend", "10.0.0.1", {"app": "frontend"})
        dest = _make_pod("dst", "backend", "10.0.0.2", {"app": "backend"})
        rule = NetworkPolicyRule(
            pod_selector={"app": "frontend"},
            namespace_selector={"name": "frontend"},
            ports=(NetworkPolicyPort(port=8080, protocol="TCP"),),
        )
        policy = NetworkPolicyInfo(
            name="allow-frontend",
            namespace="backend",
            types=("Ingress",),
            pod_selector={"app": "backend"},
            ingress_rules=(rule,),
            egress_rules=None,
        )
        verdict = analyzer.analyze(source, dest, 8080, "tcp", [policy], [source, dest], {"frontend", "backend"})
        assert verdict.allowed is True
        assert "allow-frontend" in verdict.matching_policies

    def test_ingress_rule_port_mismatch_denies(self) -> None:
        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "frontend", "10.0.0.1", {"app": "frontend"})
        dest = _make_pod("dst", "backend", "10.0.0.2", {"app": "backend"})
        rule = NetworkPolicyRule(
            pod_selector={"app": "frontend"},
            namespace_selector={"name": "frontend"},
            ports=(NetworkPolicyPort(port=9090, protocol="TCP"),),
        )
        policy = NetworkPolicyInfo(
            name="allow-frontend-9090",
            namespace="backend",
            types=("Ingress",),
            pod_selector={"app": "backend"},
            ingress_rules=(rule,),
            egress_rules=None,
        )
        verdict = analyzer.analyze(source, dest, 8080, "tcp", [policy], [source, dest], {"frontend", "backend"})
        assert verdict.allowed is False

    def test_default_deny_egress_blocks(self) -> None:
        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "restricted", "10.0.0.1", {"app": "restricted"})
        dest = _make_pod("dst", "backend", "10.0.0.2", {"app": "backend"})
        policy = NetworkPolicyInfo(
            name="deny-egress",
            namespace="restricted",
            types=("Egress",),
            pod_selector={},
            ingress_rules=None,
            egress_rules=(),
        )
        verdict = analyzer.analyze(source, dest, 8080, "tcp", [policy], [source, dest], {"restricted", "backend"})
        assert verdict.allowed is False
        assert "deny-egress" in verdict.denying_policies

    def test_ip_block_allows(self) -> None:
        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "ns1", "10.244.2.5", {"app": "src"})
        dest = _make_pod("dst", "ns2", "10.244.2.10", {"app": "dst"})
        rule = NetworkPolicyRule(
            ip_blocks=("10.244.2.0/24",),
            ports=(),
        )
        policy = NetworkPolicyInfo(
            name="allow-subnet",
            namespace="ns2",
            types=("Ingress",),
            pod_selector={"app": "dst"},
            ingress_rules=(rule,),
            egress_rules=None,
        )
        verdict = analyzer.analyze(source, dest, 8080, "tcp", [policy], [source, dest], {"ns1", "ns2"})
        assert verdict.allowed is True

    def test_mock_scenario_frontend_to_backend_allowed(self, mock_config: RuntimeConfig) -> None:
        """Test the mock cluster scenario: frontend -> backend on 8080 should be allowed."""
        inspector = KubernetesInspector(mock_config)
        snapshot = inspector.get_snapshot()
        source = inspector.get_pod("frontend", "frontend-pod")
        dest = inspector.get_pod("backend", "backend-pod")
        assert source is not None
        assert dest is not None

        analyzer = PolicyAnalyzer()
        all_ns = {p.namespace for p in snapshot.pods}
        verdict = analyzer.analyze(
            source, dest, 8080, "tcp", snapshot.network_policies, snapshot.pods, all_ns,
        )
        assert verdict.allowed is True
        assert "backend-allow-frontend-ingress" in verdict.matching_policies

    def test_mock_scenario_frontend_to_restricted_denied(self, mock_config: RuntimeConfig) -> None:
        """Test the mock cluster scenario: frontend -> restricted should be denied."""
        inspector = KubernetesInspector(mock_config)
        snapshot = inspector.get_snapshot()
        source = inspector.get_pod("frontend", "frontend-pod")
        dest = inspector.get_pod("restricted", "blocked-pod")
        assert source is not None
        assert dest is not None

        analyzer = PolicyAnalyzer()
        all_ns = {p.namespace for p in snapshot.pods}
        verdict = analyzer.analyze(
            source, dest, 3306, "tcp", snapshot.network_policies, snapshot.pods, all_ns,
        )
        assert verdict.allowed is False
        assert any("restricted" in p for p in verdict.denying_policies)

    def test_verdict_property(self) -> None:
        v_allowed = PolicyVerdict(allowed=True, confidence="CONFIRMED", reason="test")
        assert v_allowed.verdict == "ALLOWED"

        v_denied = PolicyVerdict(allowed=False, confidence="CONFIRMED", reason="test")
        assert v_denied.verdict == "DENIED"

        v_unknown = PolicyVerdict(allowed=False, confidence="UNKNOWN", reason="test")
        assert v_unknown.verdict == "UNKNOWN"

    def test_verdict_to_dict(self) -> None:
        v = PolicyVerdict(allowed=True, confidence="CONFIRMED", reason="ok", matching_policies=["p1"])
        d = v.to_dict()
        assert d["verdict"] == "ALLOWED"
        assert d["allowed"] is True
        assert d["confidence"] == "CONFIRMED"
        assert "p1" in d["matching_policies"]
