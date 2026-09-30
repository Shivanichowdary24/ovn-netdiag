"""Reporter: formats diagnostic output for CLI display and JSON export."""

from __future__ import annotations

import json
from typing import Any

from ovn_netdiag.logging_config import get_logger
from ovn_netdiag.models import CheckResult, DiagnosticReport

logger = get_logger("reporter")


class Reporter:
    """Formats diagnostic reports for CLI or JSON output."""

    @staticmethod
    def to_json(report: DiagnosticReport) -> str:
        """Serialize a diagnostic report to a JSON string."""
        return json.dumps(report.to_dict(), indent=2, sort_keys=False)

    @staticmethod
    def to_text(report: DiagnosticReport) -> str:
        """Format a diagnostic report as human-readable text."""
        lines: list[str] = []

        # Header
        lines.append("=" * 70)
        lines.append("OVN-NetDiag — Diagnostic Report")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"MODE:            {report.mode}")
        lines.append(f"SOURCE POD:      {report.source_pod}")
        lines.append(f"DESTINATION POD: {report.destination_pod}")
        lines.append(f"DESTINATION IP:  {report.destination_ip}")
        lines.append(f"PORT:            {report.port}")
        lines.append(f"PROTOCOL:        {report.protocol.upper()}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("CHECKS:")
        lines.append("-" * 70)

        for check in report.checks:
            lines.append("")
            lines.append(f"  {check.name}:")
            lines.append(f"    Verdict:    {check.verdict}")
            lines.append(f"    Confidence: {check.confidence}")
            lines.append(f"    Details:    {check.details}")
            if check.evidence:
                lines.append("    Evidence:")
                for ev in check.evidence:
                    lines.append(f"      - {ev}")

        lines.append("")
        lines.append("-" * 70)
        lines.append("DIAGNOSIS:")
        lines.append("-" * 70)
        lines.append("")
        lines.append(f"  {report.diagnosis}")
        lines.append(f"  CONFIDENCE: {report.confidence}")
        lines.append("")

        if report.mode == "MOCK":
            lines.append("=" * 70)
            lines.append("NOTE: MODE is MOCK — data is simulated, not from a real cluster.")
            lines.append("=" * 70)

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def format_cluster_info(info: dict[str, Any]) -> str:
        """Format cluster info as human-readable text."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("OVN-NetDiag — Cluster Info")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"MODE: {info.get('mode', 'UNKNOWN')}")
        lines.append("")

        lines.append("Nodes:")
        for node in info.get("nodes", []):
            lines.append(f"  {node['name']:<30} cidr={node['pod_cidr']:<20} status={node['status']}")
        lines.append("")

        lines.append("Summary:")
        lines.append(f"  Pods:              {info.get('pod_count', 0)}")
        lines.append(f"  Services:          {info.get('service_count', 0)}")
        lines.append(f"  NetworkPolicies:   {info.get('network_policy_count', 0)}")
        lines.append(f"  OVN Logical Switches: {info.get('ovn_logical_switches', 0)}")
        lines.append(f"  OVN Logical Routers:  {info.get('ovn_logical_routers', 0)}")
        lines.append(f"  OVN Port Groups:      {info.get('ovn_port_groups', 0)}")
        lines.append(f"  OVN ACLs:             {info.get('ovn_acls', 0)}")
        lines.append(f"  OVS Bridges:          {', '.join(info.get('ovs_bridges', []))}")
        lines.append(f"  OVS Flows:            {info.get('ovs_flow_count', 0)}")
        lines.append("")

        if info.get("k8s_errors"):
            lines.append("Errors:")
            for err in info["k8s_errors"]:
                lines.append(f"  - {err}")
            lines.append("")

        if info.get("mode") == "MOCK":
            lines.append("NOTE: MODE is MOCK — data is simulated, not from a real cluster.")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def format_pod_info(info: dict[str, Any]) -> str:
        """Format pod info as human-readable text."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("OVN-NetDiag — Pod Info")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"MODE: {info.get('mode', 'UNKNOWN')}")
        lines.append("")

        if info.get("error"):
            lines.append(f"Error: {info['error']}")
            return "\n".join(lines)

        pod = info.get("pod", {})
        lines.append(f"Pod: {pod.get('namespace', '')}/{pod.get('name', '')}")
        lines.append(f"  IP:       {pod.get('ip', '')}")
        lines.append(f"  Node:     {pod.get('node', '')}")
        lines.append(f"  Phase:    {pod.get('phase', '')}")
        lines.append(f"  Labels:   {pod.get('labels', {})}")
        lines.append("  Containers:")
        for c in pod.get("containers", []):
            ports = ", ".join(f"{p['port']}/{p['protocol']}" for p in c.get("ports", []))
            lines.append(f"    {c['name']}: {ports}")
        lines.append("")

        services = info.get("related_services", [])
        if services:
            lines.append("Related Services:")
            for svc in services:
                ports = ", ".join(f"{p['port']}->{p['target_port']}/{p['protocol']}" for p in svc.get("ports", []))
                lines.append(f"  {svc['name']}: cluster_ip={svc['cluster_ip']} type={svc['type']} ports=[{ports}]")
            lines.append("")

        endpoints = info.get("related_endpoints", [])
        if endpoints:
            lines.append("Related Endpoints:")
            for ep in endpoints:
                lines.append(f"  {ep['name']}: addresses={', '.join(ep['addresses'])} ready={ep['ready']}")
            lines.append("")

        policies = info.get("applicable_network_policies", [])
        if policies:
            lines.append("Applicable NetworkPolicies:")
            for pol in policies:
                lines.append(f"  {pol['name']}:")
                lines.append(f"    types: {pol['types']}")
                lines.append(f"    pod_selector: {pol['pod_selector']}")
                lines.append(f"    default_deny_ingress: {pol['is_default_deny_ingress']}")
                lines.append(f"    default_deny_egress: {pol['is_default_deny_egress']}")
            lines.append("")

        ovn_port = info.get("ovn_port")
        if ovn_port:
            lines.append("OVN Port:")
            lines.append(f"  Name: {ovn_port['name']}")
            lines.append(f"  Switch: {ovn_port['switch']}")
            lines.append(f"  Addresses: {', '.join(ovn_port['addresses'])}")
            lines.append("")

        if info.get("mode") == "MOCK":
            lines.append("NOTE: MODE is MOCK — data is simulated, not from a real cluster.")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def format_ovn_info(info: dict[str, Any]) -> str:
        """Format OVN info as human-readable text."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("OVN-NetDiag — OVN Info")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"MODE: {info.get('mode', 'UNKNOWN')}")
        lines.append("")

        lines.append("Logical Switches:")
        for ls in info.get("logical_switches", []):
            lines.append(f"  {ls['name']:<30} subnet={ls.get('subnet', '')}")
        lines.append("")

        lines.append("Logical Switch Ports:")
        for lsp in info.get("logical_switch_ports", []):
            addrs = ", ".join(lsp.get("addresses", []))
            lines.append(f"  {lsp['name']:<30} switch={lsp['switch']:<20} addrs=[{addrs}] type={lsp.get('type', '')}")
        lines.append("")

        lines.append("Port Groups:")
        for pg in info.get("port_groups", []):
            ports = ", ".join(pg.get("ports", []))
            lines.append(f"  {pg['name']:<40} ports=[{ports}]")
        lines.append("")

        lines.append("ACLs:")
        for acl in info.get("acls", []):
            lines.append(f"  [{acl['uuid'][:8]}] pg={acl['port_group']:<35} dir={acl['direction']:<12} pri={acl['priority']:<6} action={acl['action']:<15} match='{acl['match']}'")
        lines.append("")

        lines.append("Logical Routers:")
        for lr in info.get("logical_routers", []):
            lines.append(f"  {lr['name']}")
        lines.append("")

        lines.append("Logical Flows:")
        for lf in info.get("logical_flows", []):
            lines.append(f"  router={lf['router']:<20} pri={lf['priority']:<6} match='{lf['match']}' actions={lf['actions']}")
        lines.append("")

        if info.get("mode") == "MOCK":
            lines.append("NOTE: MODE is MOCK — data is simulated, not from a real cluster.")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def to_json_str(data: dict[str, Any]) -> str:
        """Serialize any dict to a pretty JSON string."""
        return json.dumps(data, indent=2, sort_keys=False)
