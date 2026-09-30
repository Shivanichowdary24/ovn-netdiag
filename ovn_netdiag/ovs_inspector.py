"""Open vSwitch inspector.

Uses ``ovs-ofctl`` via safe subprocess calls to inspect bridges and
OpenFlow flows. In mock mode, data is served from :class:`MockDataProvider`.
"""

from __future__ import annotations

import re
import subprocess
from typing import Any

from ovn_netdiag.config import RuntimeConfig, DEFAULT_OVS_TIMEOUT
from ovn_netdiag.logging_config import get_logger
from ovn_netdiag.mock_data import MockDataProvider
from ovn_netdiag.models import OvsFlow, OvsState

logger = get_logger("ovs")


def run_ovs_command(
    binary: str,
    args: list[str],
    timeout: float = DEFAULT_OVS_TIMEOUT,
) -> str:
    """Run an OVS command safely via subprocess.

    Args:
        binary: ``ovs-ofctl`` or ``ovs-vsctl``.
        args: Extra arguments to pass.
        timeout: Timeout in seconds.

    Returns:
        stdout as a string.

    Raises:
        subprocess.TimeoutExpired: If the command times out.
        subprocess.CalledProcessError: If the command returns non-zero.
        FileNotFoundError: If the binary is not installed.
    """
    cmd = [binary] + args
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        logger.error("%s failed (rc=%d): %s", binary, result.returncode, stderr)
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return result.stdout


def parse_flow_line(line: str) -> OvsFlow | None:
    """Parse a single OpenFlow flow line from ``ovs-ofctl dump-flows``.

    Expected format:
        ``cookie=0x0, priority=100, table=0, <match> actions=<actions>``
    """
    line = line.strip()
    if not line:
        return None
    # Remove leading " cookie=" part if present
    # Split on " actions=" to separate match from actions
    parts = re.split(r"\s+actions=", line, maxsplit=1)
    if len(parts) != 2:
        return None
    header_part = parts[0].strip()
    actions = parts[1].strip()

    cookie = "0x0"
    priority = 0
    table = 0
    match_parts: list[str] = []

    for token in header_part.split(","):
        token = token.strip()
        if token.startswith("cookie="):
            cookie = token[len("cookie="):]
        elif token.startswith("priority="):
            try:
                priority = int(token[len("priority="):])
            except ValueError:
                pass
        elif token.startswith("table="):
            try:
                table = int(token[len("table="):])
            except ValueError:
                pass
        else:
            match_parts.append(token)

    match_str = ",".join(match_parts).strip()
    return OvsFlow(cookie=cookie, priority=priority, table=table, match=match_str, actions=actions)


def parse_bridge_list(output: str) -> list[str]:
    """Parse ``ovs-vsctl list-br`` output into a list of bridge names."""
    bridges: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line:
            bridges.append(line)
    return bridges


class OvsInspector:
    """Open vSwitch inspector using ``ovs-ofctl``."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self._mock: MockDataProvider | None = None
        if config.is_mock:
            self._mock = MockDataProvider(config.mock_data_path)

    def get_state(self, bridge: str | None = None) -> OvsState:
        """Return OVS state. If *bridge* is given, only inspect that bridge."""
        if self.config.is_mock:
            assert self._mock is not None
            state = self._mock.ovs_state
            if bridge:
                state.bridges = [b for b in state.bridges if b.name == bridge]
                state.flows = [f for f in state.flows if _flow_for_bridge(f, bridge)]
            return state
        return self._real_get_state(bridge)

    def get_flows_for_destination(self, dest_ip: str, dest_port: int | None = None) -> list[OvsFlow]:
        """Return flows matching a destination IP and optionally port."""
        state = self.get_state()
        results: list[OvsFlow] = []
        for flow in state.flows:
            match_lower = flow.match.lower()
            if dest_ip.lower() in match_lower:
                if dest_port is None or str(dest_port) in match_lower:
                    results.append(flow)
        return results

    # ------------------------------------------------------------------
    # Real implementation
    # ------------------------------------------------------------------

    def _real_get_state(self, bridge: str | None) -> OvsState:
        from ovn_netdiag.models import OvsBridge

        state = OvsState()

        # List bridges
        try:
            out = run_ovs_command("ovs-vsctl", ["list-br"], timeout=self.config.ovs_timeout)
            bridge_names = parse_bridge_list(out)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("Could not list OVS bridges: %s", exc)
            bridge_names = []

        if bridge and bridge not in bridge_names:
            bridge_names = [bridge]

        for bn in bridge_names:
            try:
                out = run_ovs_command("ovs-vsctl", ["list-ports", bn], timeout=self.config.ovs_timeout)
                ports = tuple(out.splitlines())
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                ports = ()
            state.bridges.append(OvsBridge(name=bn, ports=ports))

            # Dump flows for this bridge
            try:
                out = run_ovs_command("ovs-ofctl", ["dump-flows", bn], timeout=self.config.ovs_timeout)
                for line in out.splitlines():
                    flow = parse_flow_line(line)
                    if flow:
                        state.flows.append(flow)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
                logger.warning("Could not dump flows for bridge %s: %s", bn, exc)

        return state


def _flow_for_bridge(flow: OvsFlow, bridge: str) -> bool:
    """In mock mode, all flows are associated with br-int by convention."""
    # Mock flows don't carry bridge info; return True for br-int
    return bridge == "br-int"
