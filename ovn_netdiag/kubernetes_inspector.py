"""Kubernetes resource inspector.

Read-only inspection of Pods, Services, Endpoints, Nodes, and NetworkPolicies.
In mock mode, data is served from :class:`MockDataProvider`.
In real mode, the Kubernetes Python client is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.logging_config import get_logger
from ovn_netdiag.mock_data import MockDataProvider
from ovn_netdiag.models import (
    EndpointInfo,
    NetworkPolicyInfo,
    NodeInfo,
    PodInfo,
    ServiceInfo,
)

logger = get_logger("kubernetes")


@dataclass
class KubernetesSnapshot:
    """Collected Kubernetes resources for a diagnostic run."""

    pods: list[PodInfo] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    endpoints: list[EndpointInfo] = field(default_factory=list)
    nodes: list[NodeInfo] = field(default_factory=list)
    network_policies: list[NetworkPolicyInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pods": [
                {
                    "name": p.name,
                    "namespace": p.namespace,
                    "ip": p.ip,
                    "node": p.node,
                    "labels": p.labels,
                    "phase": p.phase,
                    "containers": [
                        {"name": c.name, "ports": [{"port": cp.container_port, "protocol": cp.protocol} for cp in c.ports]}
                        for c in p.containers
                    ],
                }
                for p in self.pods
            ],
            "services": [
                {
                    "name": s.name,
                    "namespace": s.namespace,
                    "cluster_ip": s.cluster_ip,
                    "type": s.type,
                    "selector": s.selector,
                    "ports": [{"port": sp.port, "target_port": sp.target_port, "protocol": sp.protocol} for sp in s.ports],
                }
                for s in self.services
            ],
            "endpoints": [
                {
                    "name": e.name,
                    "namespace": e.namespace,
                    "addresses": list(e.addresses),
                    "ready": e.ready,
                    "ports": [{"port": sp.port, "protocol": sp.protocol} for sp in e.ports],
                }
                for e in self.endpoints
            ],
            "nodes": [
                {"name": n.name, "pod_cidr": n.pod_cidr, "addresses": list(n.addresses), "status": n.status}
                for n in self.nodes
            ],
            "network_policies": [
                {
                    "name": p.name,
                    "namespace": p.namespace,
                    "types": list(p.types),
                    "pod_selector": p.pod_selector,
                    "ingress_rules": _rules_to_dict(p.ingress_rules),
                    "egress_rules": _rules_to_dict(p.egress_rules),
                }
                for p in self.network_policies
            ],
            "errors": self.errors,
        }


def _rules_to_dict(rules: tuple | None) -> list[dict[str, Any]] | None:
    if rules is None:
        return None
    return [
        {
            "pod_selector": r.pod_selector,
            "namespace_selector": r.namespace_selector,
            "ip_blocks": list(r.ip_blocks),
            "ports": [{"port": p.port, "protocol": p.protocol} for p in r.ports],
        }
        for r in rules
    ]


class KubernetesInspector:
    """Read-only Kubernetes inspector.

    Args:
        config: Runtime configuration.
    """

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self._mock: MockDataProvider | None = None
        if config.is_mock:
            self._mock = MockDataProvider(config.mock_data_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_snapshot(self, namespace: str | None = None) -> KubernetesSnapshot:
        """Collect all Kubernetes resources, optionally scoped to *namespace*."""
        if self.config.is_mock:
            return self._mock_snapshot(namespace)
        return self._real_snapshot(namespace)

    def get_pod(self, namespace: str, name: str) -> PodInfo | None:
        if self.config.is_mock:
            assert self._mock is not None
            return self._mock.find_pod(namespace, name)
        return self._real_get_pod(namespace, name)

    def get_pods(self, namespace: str | None = None) -> list[PodInfo]:
        snap = self.get_snapshot(namespace)
        return snap.pods

    def get_services(self, namespace: str | None = None) -> list[ServiceInfo]:
        snap = self.get_snapshot(namespace)
        return snap.services

    def get_endpoints(self, namespace: str | None = None) -> list[EndpointInfo]:
        snap = self.get_snapshot(namespace)
        return snap.endpoints

    def get_nodes(self) -> list[NodeInfo]:
        snap = self.get_snapshot()
        return snap.nodes

    def get_network_policies(self, namespace: str | None = None) -> list[NetworkPolicyInfo]:
        snap = self.get_snapshot(namespace)
        return snap.network_policies

    # ------------------------------------------------------------------
    # Mock implementation
    # ------------------------------------------------------------------

    def _mock_snapshot(self, namespace: str | None) -> KubernetesSnapshot:
        assert self._mock is not None
        snap = KubernetesSnapshot()
        snap.pods = self._mock.all_pods() if not namespace else self._mock.pods_in_namespace(namespace)
        snap.services = self._mock.all_services() if not namespace else self._mock.services_in_namespace(namespace)
        snap.endpoints = self._mock.all_endpoints() if not namespace else self._mock.endpoints_in_namespace(namespace)
        snap.nodes = self._mock.all_nodes()
        snap.network_policies = self._mock.all_policies() if not namespace else self._mock.policies_in_namespace(namespace)
        return snap

    # ------------------------------------------------------------------
    # Real implementation (Kubernetes Python client)
    # ------------------------------------------------------------------

    def _ensure_client(self) -> None:
        """Load kubeconfig or in-cluster config. Called once before real API calls."""
        try:
            from kubernetes import config as kube_config

            if self.config.kubeconfig:
                kube_config.load_kube_config(config_file=self.config.kubeconfig)
            else:
                try:
                    kube_config.load_incluster_config()
                except Exception:
                    kube_config.load_kube_config()
        except Exception as exc:
            logger.error("Failed to load Kubernetes config: %s", exc)
            raise

    def _real_snapshot(self, namespace: str | None) -> KubernetesSnapshot:
        snap = KubernetesSnapshot()
        try:
            self._ensure_client()
            from kubernetes import client as kube_client

            core = kube_client.CoreV1Api()
            net_v1 = kube_client.NetworkingV1Api()

            ns_param = namespace or ""

            pods = core.list_namespaced_pod(ns_param) if ns_param else core.list_pod_for_all_namespaces()
            snap.pods = [_convert_k8s_pod(p) for p in pods.items]

            services = core.list_namespaced_service(ns_param) if ns_param else core.list_service_for_all_namespaces()
            snap.services = [_convert_k8s_service(s) for s in services.items]

            endpoints = core.list_namespaced_endpoints(ns_param) if ns_param else core.list_endpoints_for_all_namespaces()
            snap.endpoints = [_convert_k8s_endpoints(e) for e in endpoints.items]

            nodes = core.list_node()
            snap.nodes = [_convert_k8s_node(n) for n in nodes.items]

            policies = net_v1.list_namespaced_network_policy(ns_param) if ns_param else net_v1.list_network_policy_for_all_namespaces()
            snap.network_policies = [_convert_k8s_netpol(p) for p in policies.items]

        except Exception as exc:
            logger.error("Kubernetes API error: %s", exc)
            snap.errors.append(str(exc))
        return snap

    def _real_get_pod(self, namespace: str, name: str) -> PodInfo | None:
        try:
            self._ensure_client()
            from kubernetes import client as kube_client

            core = kube_client.CoreV1Api()
            pod = core.read_namespaced_pod(name=name, namespace=namespace)
            return _convert_k8s_pod(pod)
        except Exception as exc:
            logger.error("Failed to read pod %s/%s: %s", namespace, name, exc)
            return None


# ---------------------------------------------------------------------------
# Conversion helpers (only used in real mode)
# ---------------------------------------------------------------------------


def _convert_k8s_pod(p: Any) -> PodInfo:
    from ovn_netdiag.models import Container, ContainerPort

    containers = []
    for c in (p.spec.containers or []):
        ports = []
        for cp in (c.ports or []):
            ports.append(ContainerPort(container_port=cp.container_port, protocol=cp.protocol or "TCP"))
        containers.append(Container(name=c.name, ports=tuple(ports)))
    labels = dict(p.metadata.labels or {})
    return PodInfo(
        name=p.metadata.name,
        namespace=p.metadata.namespace,
        ip=p.status.pod_ip or "",
        node=p.spec.node_name or "",
        labels=labels,
        containers=tuple(containers),
        phase=p.status.phase or "Unknown",
    )


def _convert_k8s_service(s: Any) -> ServiceInfo:
    from ovn_netdiag.models import ServicePort

    ports = []
    for sp in (s.spec.ports or []):
        ports.append(ServicePort(port=sp.port, target_port=sp.target_port, protocol=sp.protocol or "TCP"))
    return ServiceInfo(
        name=s.metadata.name,
        namespace=s.metadata.namespace,
        cluster_ip=s.spec.cluster_ip or "",
        ports=tuple(ports),
        selector=dict(s.spec.selector or {}),
        type=s.spec.type or "ClusterIP",
    )


def _convert_k8s_endpoints(e: Any) -> EndpointInfo:
    from ovn_netdiag.models import ServicePort

    addresses: list[str] = []
    ports: list[ServicePort] = []
    for sub in (e.subsets or []):
        for addr in (sub.addresses or []):
            addresses.append(addr.ip)
        for p in (sub.ports or []):
            ports.append(ServicePort(port=p.port, target_port=p.port, protocol=p.protocol or "TCP"))
    return EndpointInfo(
        name=e.metadata.name,
        namespace=e.metadata.namespace,
        addresses=tuple(addresses),
        ports=tuple(ports),
        ready=True,
    )


def _convert_k8s_node(n: Any) -> NodeInfo:
    addresses: list[str] = []
    for addr in (n.status.addresses or []):
        addresses.append(addr.address)
    pod_cidr = n.spec.pod_cidr or ""
    return NodeInfo(
        name=n.metadata.name,
        pod_cidr=pod_cidr,
        addresses=tuple(addresses),
        status="Ready" if any(
            cond.type == "Ready" and cond.status == "True"
            for cond in (n.status.conditions or [])
        ) else "NotReady",
    )


def _convert_k8s_netpol(p: Any) -> NetworkPolicyInfo:
    from ovn_netdiag.models import NetworkPolicyPort, NetworkPolicyRule

    def _convert_rule(rule: Any) -> NetworkPolicyRule:
        pod_sel = dict(rule.pod_selector.match_labels or {}) if rule and rule.pod_selector else {}
        ns_sel = dict(rule.namespace_selector.match_labels or {}) if rule and rule.namespace_selector else {}
        ip_blocks: list[str] = []
        if rule and rule.ip_block:
            ip_blocks.append(rule.ip_block.cidr)
        ports: list[NetworkPolicyPort] = []
        if rule and rule.ports:
            for prt in rule.ports:
                ports.append(NetworkPolicyPort(
                    port=prt.port,
                    protocol=prt.protocol or "TCP",
                ))
        return NetworkPolicyRule(
            pod_selector=pod_sel,
            namespace_selector=ns_sel,
            ip_blocks=tuple(ip_blocks),
            ports=tuple(ports),
        )

    ingress: tuple[NetworkPolicyRule, ...] | None = None
    egress: tuple[NetworkPolicyRule, ...] | None = None
    if p.spec.ingress is not None:
        ingress = tuple(_convert_rule(r) for r in p.spec.ingress)
    if p.spec.egress is not None:
        egress = tuple(_convert_rule(r) for r in p.spec.egress)

    return NetworkPolicyInfo(
        name=p.metadata.name,
        namespace=p.metadata.namespace,
        types=tuple(p.spec.policy_types or []),
        pod_selector=dict(p.spec.pod_selector.match_labels or {}) if p.spec.pod_selector else {},
        ingress_rules=ingress,
        egress_rules=egress,
    )
