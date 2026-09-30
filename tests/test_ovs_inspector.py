"""Tests for OVS output parsing and inspector (mock mode)."""

from __future__ import annotations

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.models import OvsFlow, OvsState
from ovn_netdiag.ovs_inspector import (
    OvsInspector,
    parse_flow_line,
    parse_bridge_list,
)


class TestOvsParsers:
    """Test OVS command output parsers."""

    def test_parse_flow_line_full(self) -> None:
        line = "cookie=0x0, priority=100, table=0, nw_dst=10.244.2.10,tp_dst=8080 actions=output:2"
        flow = parse_flow_line(line)
        assert flow is not None
        assert flow.cookie == "0x0"
        assert flow.priority == 100
        assert flow.table == 0
        assert "nw_dst=10.244.2.10" in flow.match
        assert flow.actions == "output:2"
        assert flow.is_drop is False

    def test_parse_flow_line_drop(self) -> None:
        line = "cookie=0x0, priority=200, table=0, nw_dst=10.244.2.20 actions=drop"
        flow = parse_flow_line(line)
        assert flow is not None
        assert flow.is_drop is True

    def test_parse_flow_line_no_cookie(self) -> None:
        line = "priority=50, table=0, arp actions=FLOOD"
        flow = parse_flow_line(line)
        assert flow is not None
        assert flow.priority == 50
        assert flow.match == "arp"
        assert flow.actions == "FLOOD"

    def test_parse_flow_line_empty(self) -> None:
        assert parse_flow_line("") is None
        assert parse_flow_line("   ") is None

    def test_parse_flow_line_no_actions(self) -> None:
        assert parse_flow_line("priority=100 something") is None

    def test_parse_bridge_list(self) -> None:
        output = "br-int\nbr-ex\n"
        bridges = parse_bridge_list(output)
        assert bridges == ["br-int", "br-ex"]

    def test_parse_bridge_list_empty(self) -> None:
        assert parse_bridge_list("") == []

    def test_flow_is_normal(self) -> None:
        flow = OvsFlow(actions="NORMAL")
        assert flow.is_normal is True
        assert flow.is_drop is False


class TestOvsInspectorMock:
    """Test OvsInspector in mock mode."""

    def test_get_state(self, mock_config: RuntimeConfig) -> None:
        inspector = OvsInspector(mock_config)
        state = inspector.get_state()
        assert isinstance(state, OvsState)
        assert len(state.bridges) == 2
        assert len(state.flows) == 5

    def test_get_state_filtered_by_bridge(self, mock_config: RuntimeConfig) -> None:
        inspector = OvsInspector(mock_config)
        state = inspector.get_state(bridge="br-int")
        assert len(state.bridges) == 1
        assert state.bridges[0].name == "br-int"

    def test_get_flows_for_destination(self, mock_config: RuntimeConfig) -> None:
        inspector = OvsInspector(mock_config)
        flows = inspector.get_flows_for_destination("10.244.2.10", 8080)
        assert len(flows) >= 1
        assert any("10.244.2.10" in f.match for f in flows)

    def test_get_flows_for_destination_not_found(self, mock_config: RuntimeConfig) -> None:
        inspector = OvsInspector(mock_config)
        flows = inspector.get_flows_for_destination("99.99.99.99", 9999)
        assert len(flows) == 0

    def test_bridge_names(self, mock_config: RuntimeConfig) -> None:
        inspector = OvsInspector(mock_config)
        state = inspector.get_state()
        names = [b.name for b in state.bridges]
        assert "br-int" in names
        assert "br-ex" in names
