"""OVN Northbound / Southbound inspector.

Uses safe ``subprocess`` calls (argument lists, never ``shell=True``) to run
``ovn-nbctl`` and ``ovn-sbctl``. In mock mode, data comes from
:class:`MockDataProvider`.
"""

from __future__ import annotations

import re
import subprocess
from typing import Any

from ovn_netdiag.config import RuntimeConfig, DEFAULT_OVN_TIMEOUT
from ovn_netdiag.logging_config import get_logger
from ovn_netdiag.mock_data import MockDataProvider
from ovn_netdiag.models import OvnState

logger = get_logger("ovn")


def run_ovn_command(
    binary: str,
    args: list[str],
    timeout: float = DEFAULT_OVN_TIMEOUT,
) -> str:
    """Run an OVN command safely via subprocess.

    Args:
        binary: ``ovn-nbctl`` or ``ovn-sbctl``.
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


# ---------------------------------------------------------------------------
# Parsers for real ovn-nbctl / ovn-sbctl output
# ---------------------------------------------------------------------------


def parse_acl_line(line: str) -> dict[str, str] | None:
    """Parse a single ACL row from ``ovn-nbctl lr-acl-list`` or ``pg-acl-list``.

    Expected format:
        ``<uuid> (to-lport|from-lport) <priority> <match> <action> [log]``
    """
    line = line.strip()
    if not line:
        return None
    # Try UUID format: "xxxx (dir) pri match action"
    m = re.match(
        r"^([0-9a-f\-]{36})\s+\((to-lport|from-lport)\)\s+(\d+)\s+(.+?)\s+(allow-related|allow|drop|reject)(\s+log)?$",
        line,
        re.IGNORECASE,
    )
    if m:
        return {
            "uuid": m.group(1),
            "direction": m.group(2),
            "priority": int(m.group(3)),
            "match": m.group(4),
            "action": m.group(5),
            "log": bool(m.group(6)),
        }
    # Try non-UUID format: "pri match action"
    m2 = re.match(
        r"^(\d+)\s+(.+?)\s+(allow-related|allow|drop|reject)(\s+log)?$",
        line,
        re.IGNORECASE,
    )
    if m2:
        return {
            "uuid": "",
            "direction": "",
            "priority": int(m2.group(1)),
            "match": m2.group(2),
            "action": m2.group(3),
            "log": bool(m2.group(4)),
        }
    return None


def parse_lsp_line(line: str) -> dict[str, str] | None:
    """Parse a logical switch port line from ``ovn-nbctl lsp-list <switch>``.

    Expected format: ``<lsp_name> (<mac> <ip>)`` or just ``<lsp_name>``.
    """
    line = line.strip()
    if not line:
        return None
    m = re.match(r"^(\S+)\s+\(([^)]+)\)$", line)
    if m:
        return {"name": m.group(1), "addresses": m.group(2)}
    return {"name": line, "addresses": ""}


def parse_ls_line(line: str) -> str | None:
    """Parse a logical switch line from ``ovn-nbctl ls-list``."""
    line = line.strip()
    if not line:
        return None
    # Format: "<uuid> (ls_name)"
    m = re.match(r"^\S+\s+\(([^)]+)\)$", line)
    if m:
        return m.group(1)
    return line


def parse_lr_line(line: str) -> str | None:
    """Parse a logical router line from ``ovn-nbctl lr-list``."""
    return parse_ls_line(line)


def parse_pg_line(line: str) -> dict[str, str] | None:
    """Parse a port group line from ``ovn-nbctl pg-list``.

    Expected format: ``<uuid> (pg_name)``.
    """
    line = line.strip()
    if not line:
        return None
    m = re.match(r"^(\S+)\s+\(([^)]+)\)$", line)
    if m:
        return {"uuid": m.group(1), "name": m.group(2)}
    return {"uuid": "", "name": line}


def parse_logical_flow_line(line: str) -> dict[str, Any] | None:
    """Parse a logical flow line from ``ovn-sbctl lflow-list``.

    Expected format: ``<table>,<priority>,<match>,<actions>`` or similar.
    """
    line = line.strip()
    if not line:
        return None
    # Common format: "  <uuid> (lr_name): table=<n> priority=<p> match=(<match>) actions=(<actions>)"
    m = re.match(
        r"^\s*([0-9a-f\-]{36})\s+\(([^)]+)\):\s+table=(\d+)\s+priority=(\d+)\s+match=\(([^)]*)\)\s+actions=\(([^)]*)\)",
        line,
    )
    if m:
        return {
            "uuid": m.group(1),
            "router": m.group(2),
            "table": int(m.group(3)),
            "priority": int(m.group(4)),
            "match": m.group(5),
            "actions": m.group(6),
        }
    return None


class OvnInspector:
    """OVN Northbound/Southbound inspector."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self._mock: MockDataProvider | None = None
        if config.is_mock:
            self._mock = MockDataProvider(config.mock_data_path)

    def get_state(self) -> OvnState:
        """Return the full OVN state."""
        if self.config.is_mock:
            assert self._mock is not None
            return self._mock.ovn_state
        return self._real_get_state()

    def get_acls_for_port_group(self, pg_name: str) -> list[dict[str, Any]]:
        """Return ACLs attached to a specific port group."""
        state = self.get_state()
        return [
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
            if a.port_group == pg_name
        ]

    def find_lsp_by_ip(self, ip: str) -> str | None:
        """Find the logical switch port name for a given pod IP."""
        state = self.get_state()
        for lsp in state.logical_switch_ports:
            if ip in lsp.addresses:
                return lsp.name
        return None

    def find_switch_for_ip(self, ip: str) -> str | None:
        """Find the logical switch name that contains a given IP."""
        state = self.get_state()
        for lsp in state.logical_switch_ports:
            if ip in lsp.addresses:
                return lsp.switch
        return None

    # ------------------------------------------------------------------
    # Real implementation
    # ------------------------------------------------------------------

    def _real_get_state(self) -> OvnState:
        from ovn_netdiag.models import (
            OvnACL,
            OvnLogicalFlow,
            OvnLogicalRouter,
            OvnLogicalSwitch,
            OvnLogicalSwitchPort,
            OvnPortGroup,
        )

        state = OvnState()

        # Logical switches
        try:
            out = run_ovn_command("ovn-nbctl", ["ls-list"], timeout=self.config.ovn_timeout)
            for line in out.splitlines():
                name = parse_ls_line(line)
                if name:
                    state.logical_switches.append(OvnLogicalSwitch(name=name))
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("Could not list logical switches: %s", exc)

        # Logical switch ports
        for ls in state.logical_switches:
            try:
                out = run_ovn_command("ovn-nbctl", ["lsp-list", ls.name], timeout=self.config.ovn_timeout)
                for line in out.splitlines():
                    parsed = parse_lsp_line(line)
                    if parsed:
                        state.logical_switch_ports.append(
                            OvnLogicalSwitchPort(
                                name=parsed["name"],
                                switch=ls.name,
                                addresses=tuple(parsed.get("addresses", "").split()),
                            )
                        )
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
                logger.warning("Could not list ports for switch %s: %s", ls.name, exc)

        # Port groups
        try:
            out = run_ovn_command("ovn-nbctl", ["pg-list"], timeout=self.config.ovn_timeout)
            for line in out.splitlines():
                parsed = parse_pg_line(line)
                if parsed:
                    state.port_groups.append(OvnPortGroup(name=parsed["name"]))
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("Could not list port groups: %s", exc)

        # ACLs for each port group
        for pg in state.port_groups:
            try:
                out = run_ovn_command("ovn-nbctl", ["pg-acl-list", pg.name], timeout=self.config.ovn_timeout)
                for line in out.splitlines():
                    parsed = parse_acl_line(line)
                    if parsed:
                        state.acls.append(OvnACL(
                            uuid=parsed["uuid"],
                            port_group=pg.name,
                            direction=parsed["direction"],
                            priority=parsed["priority"],
                            match=parsed["match"],
                            action=parsed["action"],
                            log=parsed["log"],
                        ))
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
                logger.warning("Could not list ACLs for port group %s: %s", pg.name, exc)

        # Logical routers
        try:
            out = run_ovn_command("ovn-nbctl", ["lr-list"], timeout=self.config.ovn_timeout)
            for line in out.splitlines():
                name = parse_lr_line(line)
                if name:
                    state.logical_routers.append(OvnLogicalRouter(name=name))
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("Could not list logical routers: %s", exc)

        # Logical flows (Southbound DB)
        try:
            out = run_ovn_command("ovn-sbctl", ["lflow-list"], timeout=self.config.ovn_timeout)
            for line in out.splitlines():
                parsed = parse_logical_flow_line(line)
                if parsed:
                    state.logical_flows.append(OvnLogicalFlow(
                        uuid=parsed["uuid"],
                        router=parsed["router"],
                        match=parsed["match"],
                        actions=parsed["actions"],
                        priority=parsed.get("priority", 100),
                    ))
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("Could not list logical flows: %s", exc)

        return state
