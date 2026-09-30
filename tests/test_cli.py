"""Tests for CLI commands and argument parsing."""

from __future__ import annotations

import json
import sys

import pytest

from ovn_netdiag.cli import build_parser, main


class TestCLIParser:
    """Test argument parsing."""

    def test_help_no_command(self) -> None:
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None

    def test_diagnose_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "diagnose",
            "--namespace", "frontend",
            "--source", "frontend-pod",
            "--destination", "backend-pod",
            "--port", "8080",
            "--protocol", "tcp",
            "--mock",
        ])
        assert args.command == "diagnose"
        assert args.namespace == "frontend"
        assert args.source == "frontend-pod"
        assert args.destination == "backend-pod"
        assert args.port == 8080
        assert args.mock is True

    def test_cluster_info_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["cluster-info", "--mock"])
        assert args.command == "cluster-info"
        assert args.mock is True

    def test_pod_info_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "pod-info",
            "--namespace", "frontend",
            "--pod", "frontend-pod",
            "--mock",
        ])
        assert args.command == "pod-info"
        assert args.namespace == "frontend"
        assert args.pod == "frontend-pod"

    def test_ovn_info_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["ovn-info", "--mock"])
        assert args.command == "ovn-info"

    def test_verbose_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["cluster-info", "--mock", "--verbose"])
        assert args.verbose is True

    def test_json_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["cluster-info", "--mock", "--json"])
        assert args.json_output is True


class TestCLICommands:
    """Test CLI command execution."""

    def test_diagnose_mock(self, capsys) -> None:
        exit_code = main([
            "diagnose",
            "--namespace", "frontend",
            "--source", "frontend-pod",
            "--destination", "backend-pod",
            "--port", "8080",
            "--mock",
        ])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "OVN-NetDiag" in out
        assert "MOCK" in out

    def test_diagnose_mock_json(self, capsys) -> None:
        exit_code = main([
            "diagnose",
            "--namespace", "frontend",
            "--source", "frontend-pod",
            "--destination", "backend-pod",
            "--port", "8080",
            "--mock",
            "--json",
        ])
        assert exit_code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["mode"] == "MOCK"
        assert data["source_pod"] == "frontend/frontend-pod"

    def test_cluster_info_mock(self, capsys) -> None:
        exit_code = main(["cluster-info", "--mock"])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "Cluster Info" in out
        assert "MOCK" in out

    def test_cluster_info_mock_json(self, capsys) -> None:
        exit_code = main(["cluster-info", "--mock", "--json"])
        assert exit_code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["mode"] == "MOCK"
        assert data["pod_count"] == 4

    def test_pod_info_mock(self, capsys) -> None:
        exit_code = main([
            "pod-info",
            "--namespace", "frontend",
            "--pod", "frontend-pod",
            "--mock",
        ])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "frontend-pod" in out
        assert "10.244.1.5" in out

    def test_pod_info_mock_json(self, capsys) -> None:
        exit_code = main([
            "pod-info",
            "--namespace", "frontend",
            "--pod", "frontend-pod",
            "--mock",
            "--json",
        ])
        assert exit_code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["pod"]["name"] == "frontend-pod"

    def test_ovn_info_mock(self, capsys) -> None:
        exit_code = main(["ovn-info", "--mock"])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "OVN Info" in out
        assert "Logical Switches:" in out

    def test_ovn_info_mock_json(self, capsys) -> None:
        exit_code = main(["ovn-info", "--mock", "--json"])
        assert exit_code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["mode"] == "MOCK"
        assert len(data["acls"]) == 4

    def test_no_command_prints_help(self, capsys) -> None:
        exit_code = main([])
        assert exit_code == 1
        out = capsys.readouterr().out
        assert "usage:" in out.lower() or "Available commands" in out

    def test_diagnose_missing_required_args(self, capsys) -> None:
        with pytest.raises(SystemExit):
            main(["diagnose", "--mock"])
