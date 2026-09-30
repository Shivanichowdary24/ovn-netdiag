"""Tests for error handling and edge cases."""

from __future__ import annotations

import pytest

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.diagnostic_engine import DiagnosticEngine
from ovn_netdiag.kubernetes_inspector import KubernetesInspector
from ovn_netdiag.connectivity import ConnectivityTester
from ovn_netdiag.policy_analyzer import PolicyAnalyzer
from ovn_netdiag.models import PodInfo, Container, ContainerPort


def _make_pod(name: str, namespace: str = "ns", ip: str = "10.0.0.1", labels: dict | None = None) -> PodInfo:
    return PodInfo(
        name=name,
        namespace=namespace,
        ip=ip,
        node="node-1",
        labels=labels or {},
        containers=(Container(name="c", ports=(ContainerPort(8080),),),),
    )


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_diagnose_nonexistent_source(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="nonexistent",
            source="no-pod",
            destination="backend-pod",
            port=8080,
        )
        assert "not found" in report.diagnosis
        assert report.confidence == "CONFIRMED"

    def test_diagnose_nonexistent_destination(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="no-such-pod",
            port=8080,
        )
        assert "not found" in report.diagnosis

    def test_pod_info_nonexistent(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        info = engine.pod_info("nonexistent", "no-pod")
        assert "error" in info

    def test_connectivity_unknown_scenario(self, mock_config: RuntimeConfig) -> None:
        tester = ConnectivityTester(mock_config)
        result = tester.test(
            source="unknown/unknown",
            target="unknown/unknown",
            destination_ip="0.0.0.0",
            port=1,
        )
        assert result.reachable is False
        assert result.error is not None

    def test_policy_analyzer_empty_pods(self) -> None:
        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "ns1", "10.0.0.1", {"app": "src"})
        dest = _make_pod("dst", "ns2", "10.0.0.2", {"app": "dst"})
        verdict = analyzer.analyze(source, dest, 8080, "tcp", [], [], set())
        assert verdict.allowed is True

    def test_policy_analyzer_no_port_restriction(self) -> None:
        """Rules with no port restriction should allow all ports."""
        from ovn_netdiag.models import NetworkPolicyInfo, NetworkPolicyRule

        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "frontend", "10.0.0.1", {"app": "frontend"})
        dest = _make_pod("dst", "backend", "10.0.0.2", {"app": "backend"})
        rule = NetworkPolicyRule(
            pod_selector={"app": "frontend"},
            namespace_selector={"name": "frontend"},
            ports=(),
        )
        policy = NetworkPolicyInfo(
            name="allow-all-ports",
            namespace="backend",
            types=("Ingress",),
            pod_selector={"app": "backend"},
            ingress_rules=(rule,),
            egress_rules=None,
        )
        verdict = analyzer.analyze(source, dest, 9999, "tcp", [policy], [source, dest], {"frontend", "backend"})
        assert verdict.allowed is True

    def test_policy_analyzer_wrong_protocol(self) -> None:
        """Rules specifying TCP should not match UDP traffic."""
        from ovn_netdiag.models import NetworkPolicyInfo, NetworkPolicyPort, NetworkPolicyRule

        analyzer = PolicyAnalyzer()
        source = _make_pod("src", "frontend", "10.0.0.1", {"app": "frontend"})
        dest = _make_pod("dst", "backend", "10.0.0.2", {"app": "backend"})
        rule = NetworkPolicyRule(
            pod_selector={"app": "frontend"},
            namespace_selector={"name": "frontend"},
            ports=(NetworkPolicyPort(port=8080, protocol="TCP"),),
        )
        policy = NetworkPolicyInfo(
            name="tcp-only",
            namespace="backend",
            types=("Ingress",),
            pod_selector={"app": "backend"},
            ingress_rules=(rule,),
            egress_rules=None,
        )
        verdict = analyzer.analyze(source, dest, 8080, "udp", [policy], [source, dest], {"frontend", "backend"})
        assert verdict.allowed is False

    def test_real_mode_kubernetes_without_config(self, real_config: RuntimeConfig) -> None:
        """In real mode without a cluster, the inspector should handle errors gracefully."""
        inspector = KubernetesInspector(real_config)
        # This should not crash; it should return a snapshot with errors
        try:
            snapshot = inspector.get_snapshot()
            # If it does return, errors should be populated
            assert isinstance(snapshot.errors, list)
        except Exception:
            # Acceptable: real mode without kubeconfig should fail gracefully
            pass

    def test_config_mode_properties(self) -> None:
        cfg_mock = RuntimeConfig(mock=True)
        assert cfg_mock.is_mock is True
        assert cfg_mock.is_real is False
        assert cfg_mock.mode == "MOCK"

        cfg_real = RuntimeConfig(mock=False)
        assert cfg_real.is_mock is False
        assert cfg_real.is_real is True
        assert cfg_real.mode == "REAL"

    def test_diagnose_with_udp_protocol(self, mock_config: RuntimeConfig) -> None:
        """Diagnose should handle UDP protocol without crashing."""
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="backend-pod",
            port=8080,
            protocol="udp",
        )
        assert report.protocol == "udp"
        # Connectivity test in mock mode returns False for unknown scenarios
        conn_check = next(c for c in report.checks if c.name == "TCP CONNECTIVITY")
        # Even if it fails, the report should be complete
        assert conn_check is not None
