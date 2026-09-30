"""Mock data provider for OVN-NetDiag.

Loads a JSON fixture describing a realistic OVN-Kubernetes cluster
and converts it into the typed data models used throughout the tool.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.logging_config import get_logger
from ovn_netdiag.models import (
    Container,
    ContainerPort,
    EndpointInfo,
    NetworkPolicyInfo,
    NetworkPolicyPort,
    NetworkPolicyRule,
    NodeInfo,
    OvnACL,
    OvnLogicalFlow,
    OvnLogicalRouter,
    OvnLogicalSwitch,
    OvnLogicalSwitchPort,
    OvnPortGroup,
    OvnState,
    OvsBridge,
    OvsFlow,
    OvsState,
    PodInfo,
    ServiceInfo,
    ServicePort,
)

logger = get_logger("mock_data")

DEFAULT_MOCK_PATH: Path = Path(__file__).resolve().parent.parent / "examples" / "mock_cluster.json"


def load_mock_json(path: str | Path | None = None) -> dict[str, Any]:
    """Load the mock cluster JSON from *path* or the default location."""
    p = Path(path) if path else DEFAULT_MOCK_PATH
    logger.debug("Loading mock data from %s", p)
    text = p.read_text(encoding="utf-8")
    return json.loads(text)


def parse_pods(raw: list[dict[str, Any]]) -> list[PodInfo]:
    pods: list[PodInfo] = []
    for item in raw:
        containers = tuple(
            Container(
                name=c.get("name", ""),
                ports=tuple(
                    ContainerPort(
                        container_port=cp.get("container_port", 0),
                        protocol=cp.get("protocol", "TCP"),
                    )
                    for cp in c.get("ports", [])
                ),
            )
            for c in item.get("containers", [])
        )
        pods.append(
            PodInfo(
                name=item["name"],
                namespace=item["namespace"],
                ip=item.get("ip", ""),
                node=item.get("node", ""),
                labels=dict(item.get("labels", {})),
                containers=containers,
                phase=item.get("phase", "Running"),
            )
        )
    return pods


def parse_services(raw: list[dict[str, Any]]) -> list[ServiceInfo]:
    services: list[ServiceInfo] = []
    for item in raw:
        ports = tuple(
            ServicePort(
                port=sp.get("port", 0),
                target_port=sp.get("target_port", 0),
                protocol=sp.get("protocol", "TCP"),
            )
            for sp in item.get("ports", [])
        )
        services.append(
            ServiceInfo(
                name=item["name"],
                namespace=item["namespace"],
                cluster_ip=item.get("cluster_ip", ""),
                ports=ports,
                selector=dict(item.get("selector", {})),
                type=item.get("type", "ClusterIP"),
            )
        )
    return services


def parse_endpoints(raw: list[dict[str, Any]]) -> list[EndpointInfo]:
    endpoints: list[EndpointInfo] = []
    for item in raw:
        ports = tuple(
            ServicePort(
                port=sp.get("port", 0),
                target_port=sp.get("target_port", sp.get("port", 0)),
                protocol=sp.get("protocol", "TCP"),
            )
            for sp in item.get("ports", [])
        )
        endpoints.append(
            EndpointInfo(
                name=item["name"],
                namespace=item["namespace"],
                addresses=tuple(item.get("addresses", [])),
                ports=ports,
                ready=item.get("ready", True),
            )
        )
    return endpoints


def parse_nodes(raw: list[dict[str, Any]]) -> list[NodeInfo]:
    nodes: list[NodeInfo] = []
    for item in raw:
        nodes.append(
            NodeInfo(
                name=item["name"],
                pod_cidr=item.get("pod_cidr", ""),
                addresses=tuple(item.get("addresses", [])),
                status=item.get("status", "Ready"),
            )
        )
    return nodes


def parse_network_policies(raw: list[dict[str, Any]]) -> list[NetworkPolicyInfo]:
    policies: list[NetworkPolicyInfo] = []
    for item in raw:
        ingress: tuple[NetworkPolicyRule, ...] | None = None
        egress: tuple[NetworkPolicyRule, ...] | None = None

        if item.get("ingress_rules") is not None:
            ingress = tuple(_parse_rule(r) for r in item["ingress_rules"])
        if item.get("egress_rules") is not None:
            egress = tuple(_parse_rule(r) for r in item["egress_rules"])

        policies.append(
            NetworkPolicyInfo(
                name=item["name"],
                namespace=item["namespace"],
                types=tuple(item.get("types", [])),
                pod_selector=dict(item.get("pod_selector", {})),
                ingress_rules=ingress,
                egress_rules=egress,
            )
        )
    return policies


def _parse_rule(raw: dict[str, Any]) -> NetworkPolicyRule:
    return NetworkPolicyRule(
        pod_selector=dict(raw.get("pod_selector", {})),
        namespace_selector=dict(raw.get("namespace_selector", {})),
        ip_blocks=tuple(raw.get("ip_blocks", [])),
        ports=tuple(
            NetworkPolicyPort(port=p.get("port"), protocol=p.get("protocol", "TCP"))
            for p in raw.get("ports", [])
        ),
    )


def parse_ovn_state(raw: dict[str, Any]) -> OvnState:
    state = OvnState()
    state.logical_switches = [
        OvnLogicalSwitch(name=ls["name"], subnet=ls.get("subnet", ""))
        for ls in raw.get("logical_switches", [])
    ]
    state.logical_switch_ports = [
        OvnLogicalSwitchPort(
            name=lsp["name"],
            switch=lsp.get("switch", ""),
            addresses=tuple(lsp.get("addresses", [])),
            type=lsp.get("type", ""),
        )
        for lsp in raw.get("logical_switch_ports", [])
    ]
    state.port_groups = [
        OvnPortGroup(name=pg["name"], ports=tuple(pg.get("ports", [])))
        for pg in raw.get("port_groups", [])
    ]
    state.acls = [
        OvnACL(
            uuid=acl["uuid"],
            port_group=acl.get("port_group", ""),
            direction=acl.get("direction", ""),
            priority=acl.get("priority", 0),
            match=acl.get("match", ""),
            action=acl.get("action", ""),
            log=acl.get("log", False),
        )
        for acl in raw.get("acls", [])
    ]
    state.logical_routers = [
        OvnLogicalRouter(name=lr["name"], ports=tuple(lr.get("ports", [])))
        for lr in raw.get("logical_routers", [])
    ]
    state.logical_flows = [
        OvnLogicalFlow(
            uuid=lf["uuid"],
            router=lf.get("router", ""),
            match=lf.get("match", ""),
            actions=lf.get("actions", ""),
            priority=lf.get("priority", 100),
        )
        for lf in raw.get("logical_flows", [])
    ]
    return state


def parse_ovs_state(raw: dict[str, Any]) -> OvsState:
    state = OvsState()
    state.bridges = [
        OvsBridge(
            name=b["name"],
            datapath_id=b.get("datapath_id", ""),
            ports=tuple(b.get("ports", [])),
        )
        for b in raw.get("bridges", [])
    ]
    state.flows = [
        OvsFlow(
            cookie=f.get("cookie", "0x0"),
            priority=f.get("priority", 0),
            table=f.get("table", 0),
            match=f.get("match", ""),
            actions=f.get("actions", ""),
        )
        for f in raw.get("flows", [])
    ]
    return state


class MockDataProvider:
    """Provides typed mock data for all inspectors."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._raw = load_mock_json(path)
        self._pods: list[PodInfo] = parse_pods(self._raw.get("pods", []))
        self._services: list[ServiceInfo] = parse_services(self._raw.get("services", []))
        self._endpoints: list[EndpointInfo] = parse_endpoints(self._raw.get("endpoints", []))
        self._nodes: list[NodeInfo] = parse_nodes(self._raw.get("nodes", []))
        self._policies: list[NetworkPolicyInfo] = parse_network_policies(
            self._raw.get("network_policies", [])
        )
        self._ovn: OvnState = parse_ovn_state(self._raw.get("ovn", {}))
        self._ovs: OvsState = parse_ovs_state(self._raw.get("ovs", {}))

    @property
    def pods(self) -> list[PodInfo]:
        return self._pods

    @property
    def services(self) -> list[ServiceInfo]:
        return self._services

    @property
    def endpoints(self) -> list[EndpointInfo]:
        return self._endpoints

    @property
    def nodes(self) -> list[NodeInfo]:
        return self._nodes

    @property
    def network_policies(self) -> list[NetworkPolicyInfo]:
        return self._policies

    @property
    def ovn_state(self) -> OvnState:
        return self._ovn

    @property
    def ovs_state(self) -> OvsState:
        return self._ovs

    def find_pod(self, namespace: str, name: str) -> PodInfo | None:
        for pod in self._pods:
            if pod.namespace == namespace and pod.name == name:
                return pod
        return None

    def pods_in_namespace(self, namespace: str) -> list[PodInfo]:
        return [p for p in self._pods if p.namespace == namespace]

    def services_in_namespace(self, namespace: str) -> list[ServiceInfo]:
        return [s for s in self._services if s.namespace == namespace]

    def endpoints_in_namespace(self, namespace: str) -> list[EndpointInfo]:
        return [e for e in self._endpoints if e.namespace == namespace]

    def policies_in_namespace(self, namespace: str) -> list[NetworkPolicyInfo]:
        return [p for p in self._policies if p.namespace == namespace]

    def all_pods(self) -> list[PodInfo]:
        return list(self._pods)

    def all_nodes(self) -> list[NodeInfo]:
        return list(self._nodes)

    def all_services(self) -> list[ServiceInfo]:
        return list(self._services)

    def all_endpoints(self) -> list[EndpointInfo]:
        return list(self._endpoints)

    def all_policies(self) -> list[NetworkPolicyInfo]:
        return list(self._policies)
