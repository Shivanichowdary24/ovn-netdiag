"""Tests for the diagnostic engine correlation logic."""

from __future__ import annotations

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.diagnostic_engine import DiagnosticEngine
from ovn_netdiag.models import DiagnosticReport, CheckResult


class TestDiagnosticEngineMock:
    """Test DiagnosticEngine in mock mode."""

    def test_diagnose_frontend_to_backend_allowed(self, mock_config: RuntimeConfig) -> None:
        """Frontend -> backend on 8080 should be allowed and reachable."""
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="backend-pod",
            port=8080,
            protocol="tcp",
        )
        assert isinstance(report, DiagnosticReport)
        assert report.mode == "MOCK"
        assert report.source_pod == "frontend/frontend-pod"
        assert report.destination_ip == "10.244.2.10"
        assert report.port == 8080

        check_names = [c.name for c in report.checks]
        assert "KUBERNETES" in check_names
        assert "NETWORK POLICY" in check_names
        assert "OVN ACL" in check_names
        assert "OVS FLOW" in check_names
        assert "TCP CONNECTIVITY" in check_names

        # This scenario should be allowed and reachable
        policy_check = next(c for c in report.checks if c.name == "NETWORK POLICY")
        assert policy_check.verdict == "PASS"

        conn_check = next(c for c in report.checks if c.name == "TCP CONNECTIVITY")
        assert conn_check.verdict == "PASS"

        assert "reachable" in report.diagnosis.lower()
        assert report.confidence == "CONFIRMED"

    def test_diagnose_frontend_to_restricted_denied(self, mock_config: RuntimeConfig) -> None:
        """Frontend -> restricted on 3306 should be denied by NetworkPolicy."""
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="blocked-pod",
            port=3306,
            protocol="tcp",
        )
        assert report.destination_ip == "10.244.2.20"

        policy_check = next(c for c in report.checks if c.name == "NETWORK POLICY")
        assert policy_check.verdict == "DENIED"

        conn_check = next(c for c in report.checks if c.name == "TCP CONNECTIVITY")
        assert conn_check.verdict == "FAILED"

        assert "NetworkPolicy" in report.diagnosis
        assert report.confidence == "CONFIRMED"

    def test_diagnose_source_pod_not_found(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="nonexistent",
            source="no-pod",
            destination="backend-pod",
            port=8080,
        )
        assert report.diagnosis == "Source pod nonexistent/no-pod not found in the cluster."
        assert report.confidence == "CONFIRMED"

    def test_diagnose_destination_pod_not_found(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="nonexistent-pod",
            port=8080,
        )
        assert "not found" in report.diagnosis

    def test_cluster_info(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        info = engine.cluster_info()
        assert info["mode"] == "MOCK"
        assert info["pod_count"] == 4
        assert info["service_count"] == 2
        assert info["network_policy_count"] == 4
        assert info["ovn_logical_switches"] == 3
        assert info["ovn_acls"] == 4
        assert "br-int" in info["ovs_bridges"]

    def test_pod_info(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        info = engine.pod_info("frontend", "frontend-pod")
        assert info["mode"] == "MOCK"
        assert info["pod"]["name"] == "frontend-pod"
        assert info["pod"]["ip"] == "10.244.1.5"
        assert len(info["pod"]["containers"]) == 1
        assert info["ovn_port"] is not None
        assert info["ovn_port"]["name"] == "frontend-pod_frontend"

    def test_pod_info_not_found(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        info = engine.pod_info("nonexistent", "no-pod")
        assert "error" in info

    def test_ovn_info(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        info = engine.ovn_info()
        assert info["mode"] == "MOCK"
        assert len(info["logical_switches"]) == 3
        assert len(info["acls"]) == 4
        assert len(info["logical_routers"]) == 1

    def test_report_to_dict(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="backend-pod",
            port=8080,
        )
        d = report.to_dict()
        assert d["mode"] == "MOCK"
        assert d["source_pod"] == "frontend/frontend-pod"
        assert d["port"] == 8080
        assert isinstance(d["checks"], list)
        assert len(d["checks"]) == 5
        assert "diagnosis" in d
        assert "confidence" in d

    def test_report_has_mock_mode(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="backend-pod",
            port=8080,
        )
        assert report.mode == "MOCK"
