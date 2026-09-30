"""Tests for OVN output parsing and inspector (mock mode)."""

from __future__ import annotations

import subprocess

import pytest

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.ovn_inspector import (
    OvnInspector,
    parse_acl_line,
    parse_lsp_line,
    parse_ls_line,
    parse_pg_line,
    parse_logical_flow_line,
    run_ovn_command,
)
from ovn_netdiag.models import OvnState


class TestOvnParsers:
    """Test OVN command output parsers."""

    def test_parse_acl_line_with_uuid(self) -> None:
        line = "a1b2c3d4-e5f6-7890-abcd-ef1234567890 (to-lport) 1001 ip4.src == 10.0.0.1 && tcp.dst == 8080 allow-related log"
        result = parse_acl_line(line)
        assert result is not None
        assert result["direction"] == "to-lport"
        assert result["priority"] == 1001
        assert result["action"] == "allow-related"
        assert result["log"] is True

    def test_parse_acl_line_without_uuid(self) -> None:
        line = "1000 ip drop"
        result = parse_acl_line(line)
        assert result is not None
        assert result["priority"] == 1000
        assert result["action"] == "drop"

    def test_parse_acl_line_empty(self) -> None:
        assert parse_acl_line("") is None
        assert parse_acl_line("   ") is None

    def test_parse_acl_line_invalid(self) -> None:
        assert parse_acl_line("this is not an acl") is None

    def test_parse_lsp_line_with_addresses(self) -> None:
        line = "frontend-pod_frontend (0a:00:00:00:00:01 10.244.1.5)"
        result = parse_lsp_line(line)
        assert result is not None
        assert result["name"] == "frontend-pod_frontend"
        assert "10.244.1.5" in result["addresses"]

    def test_parse_lsp_line_without_addresses(self) -> None:
        line = "some-port"
        result = parse_lsp_line(line)
        assert result is not None
        assert result["name"] == "some-port"
        assert result["addresses"] == ""

    def test_parse_ls_line(self) -> None:
        line = "abc123 (node-worker-1)"
        assert parse_ls_line(line) == "node-worker-1"
        line2 = "plain-name"
        assert parse_ls_line(line2) == "plain-name"
        assert parse_ls_line("") is None

    def test_parse_pg_line(self) -> None:
        line = "abc123 (backendIngressDefaultDeny)"
        result = parse_pg_line(line)
        assert result is not None
        assert result["name"] == "backendIngressDefaultDeny"

    def test_parse_logical_flow_line(self) -> None:
        line = "  a1b2c3d4-e5f6-7890-abcd-ef1234567890 (ovn-cluster): table=0 priority=100 match=(ip4.dst == 10.244.2.10) actions=(output)"
        result = parse_logical_flow_line(line)
        assert result is not None
        assert result["router"] == "ovn-cluster"
        assert result["priority"] == 100
        assert result["match"] == "ip4.dst == 10.244.2.10"
        assert result["actions"] == "output"

    def test_parse_logical_flow_line_empty(self) -> None:
        assert parse_logical_flow_line("") is None
        assert parse_logical_flow_line("garbage") is None


class TestOvnInspectorMock:
    """Test OvnInspector in mock mode."""

    def test_get_state(self, mock_config: RuntimeConfig) -> None:
        inspector = OvnInspector(mock_config)
        state = inspector.get_state()
        assert isinstance(state, OvnState)
        assert len(state.logical_switches) == 3
        assert len(state.logical_switch_ports) == 4
        assert len(state.port_groups) == 3
        assert len(state.acls) == 4
        assert len(state.logical_routers) == 1
        assert len(state.logical_flows) == 3

    def test_find_lsp_by_ip(self, mock_config: RuntimeConfig) -> None:
        inspector = OvnInspector(mock_config)
        lsp = inspector.find_lsp_by_ip("10.244.1.5")
        assert lsp == "frontend-pod_frontend"

    def test_find_lsp_by_ip_not_found(self, mock_config: RuntimeConfig) -> None:
        inspector = OvnInspector(mock_config)
        assert inspector.find_lsp_by_ip("1.1.1.1") is None

    def test_find_switch_for_ip(self, mock_config: RuntimeConfig) -> None:
        inspector = OvnInspector(mock_config)
        switch = inspector.find_switch_for_ip("10.244.2.10")
        assert switch == "node-worker-2"

    def test_get_acls_for_port_group(self, mock_config: RuntimeConfig) -> None:
        inspector = OvnInspector(mock_config)
        acls = inspector.get_acls_for_port_group("backendIngressDefaultDeny")
        assert len(acls) == 2
        assert any(a["action"] == "drop" for a in acls)
        assert any(a["action"] == "allow-related" for a in acls)

    def test_get_acls_for_nonexistent_pg(self, mock_config: RuntimeConfig) -> None:
        inspector = OvnInspector(mock_config)
        acls = inspector.get_acls_for_port_group("nonexistent")
        assert len(acls) == 0


class TestRunOvnCommand:
    """Test the run_ovn_command function with real subprocess (using echo as a stand-in)."""

    def test_command_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            run_ovn_command("nonexistent-binary-xyz", ["arg1"], timeout=2.0)

    def test_command_timeout(self) -> None:
        with pytest.raises(subprocess.TimeoutExpired):
            run_ovn_command("sleep", ["10"], timeout=0.5)
