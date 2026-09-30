"""Tests for JSON reporting output."""

from __future__ import annotations

import json

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.diagnostic_engine import DiagnosticEngine
from ovn_netdiag.models import CheckResult, DiagnosticReport
from ovn_netdiag.reporter import Reporter


class TestReporterJSON:
    """Test JSON output from the Reporter."""

    def test_to_json_valid(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="backend-pod",
            port=8080,
        )
        output = Reporter.to_json(report)
        data = json.loads(output)
        assert data["mode"] == "MOCK"
        assert data["source_pod"] == "frontend/frontend-pod"
        assert data["destination_pod"] == "backend/backend-pod"
        assert data["port"] == 8080
        assert isinstance(data["checks"], list)
        for check in data["checks"]:
            assert "name" in check
            assert "verdict" in check
            assert "confidence" in check
            assert "details" in check

    def test_to_json_str(self) -> None:
        data = {"key": "value", "nested": {"a": 1}}
        result = Reporter.to_json_str(data)
        parsed = json.loads(result)
        assert parsed == data

    def test_to_text_contains_key_sections(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="backend-pod",
            port=8080,
        )
        text = Reporter.to_text(report)
        assert "OVN-NetDiag" in text
        assert "SOURCE POD:" in text
        assert "DESTINATION POD:" in text
        assert "CHECKS:" in text
        assert "DIAGNOSIS:" in text
        assert "CONFIDENCE:" in text
        assert "MODE:" in text
        assert "MOCK" in text

    def test_to_text_contains_mock_note(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        report = engine.diagnose(
            namespace="frontend",
            source="frontend-pod",
            destination="backend-pod",
            port=8080,
        )
        text = Reporter.to_text(report)
        assert "MODE is MOCK" in text

    def test_format_cluster_info(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        info = engine.cluster_info()
        text = Reporter.format_cluster_info(info)
        assert "Cluster Info" in text
        assert "Nodes:" in text
        assert "Summary:" in text
        assert "Pods:" in text
        assert "MOCK" in text

    def test_format_pod_info(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        info = engine.pod_info("frontend", "frontend-pod")
        text = Reporter.format_pod_info(info)
        assert "Pod Info" in text
        assert "frontend-pod" in text
        assert "10.244.1.5" in text

    def test_format_pod_info_error(self) -> None:
        info = {"mode": "MOCK", "error": "Pod not found"}
        text = Reporter.format_pod_info(info)
        assert "Error:" in text
        assert "Pod not found" in text

    def test_format_ovn_info(self, mock_config: RuntimeConfig) -> None:
        engine = DiagnosticEngine(mock_config)
        info = engine.ovn_info()
        text = Reporter.format_ovn_info(info)
        assert "OVN Info" in text
        assert "Logical Switches:" in text
        assert "ACLs:" in text
        assert "node-worker-1" in text

    def test_manual_report_to_json(self) -> None:
        report = DiagnosticReport(
            source_pod="ns/src",
            destination_pod="ns/dst",
            destination_ip="10.0.0.1",
            port=80,
            protocol="tcp",
            mode="MOCK",
        )
        report.add_check(CheckResult(
            name="TEST",
            verdict="PASS",
            confidence="CONFIRMED",
            details="All good",
        ))
        report.diagnosis = "Everything works"
        report.confidence = "CONFIRMED"

        output = Reporter.to_json(report)
        data = json.loads(output)
        assert data["checks"][0]["name"] == "TEST"
        assert data["checks"][0]["verdict"] == "PASS"
        assert data["diagnosis"] == "Everything works"
