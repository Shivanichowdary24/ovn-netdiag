"""Tests for the Kubernetes inspector using mock data."""

from __future__ import annotations

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.kubernetes_inspector import KubernetesInspector, KubernetesSnapshot


class TestKubernetesInspectorMock:
    """Test KubernetesInspector in mock mode."""

    def test_get_snapshot_returns_pods(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        snapshot = inspector.get_snapshot()
        assert isinstance(snapshot, KubernetesSnapshot)
        assert len(snapshot.pods) == 4

    def test_get_snapshot_filtered_by_namespace(self, mock_config: RuntimeConfig) -> None:
        mock_config.namespace = "frontend"
        inspector = KubernetesInspector(mock_config)
        snapshot = inspector.get_snapshot("frontend")
        assert all(p.namespace == "frontend" for p in snapshot.pods)
        assert len(snapshot.pods) == 1

    def test_find_pod(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        pod = inspector.get_pod("frontend", "frontend-pod")
        assert pod is not None
        assert pod.name == "frontend-pod"
        assert pod.namespace == "frontend"
        assert pod.ip == "10.244.1.5"
        assert pod.node == "node-worker-1"

    def test_find_pod_not_found(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        pod = inspector.get_pod("nonexistent", "no-pod")
        assert pod is None

    def test_get_services(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        services = inspector.get_services()
        assert len(services) == 2
        assert any(s.name == "backend-service" for s in services)

    def test_get_endpoints(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        endpoints = inspector.get_endpoints()
        assert len(endpoints) == 2
        ep = endpoints[0]
        assert len(ep.addresses) > 0

    def test_get_nodes(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        nodes = inspector.get_nodes()
        assert len(nodes) == 3
        assert all(n.status == "Ready" for n in nodes)

    def test_get_network_policies(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        policies = inspector.get_network_policies()
        assert len(policies) == 4

    def test_snapshot_to_dict(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        snapshot = inspector.get_snapshot()
        d = snapshot.to_dict()
        assert "pods" in d
        assert "services" in d
        assert "endpoints" in d
        assert "nodes" in d
        assert "network_policies" in d
        assert isinstance(d["pods"], list)

    def test_pod_matches_selector(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        pod = inspector.get_pod("frontend", "frontend-pod")
        assert pod is not None
        assert pod.matches_selector({"app": "frontend"}) is True
        assert pod.matches_selector({"app": "backend"}) is False
        assert pod.matches_selector({}) is True

    def test_pod_has_containers_with_ports(self, mock_config: RuntimeConfig) -> None:
        inspector = KubernetesInspector(mock_config)
        pod = inspector.get_pod("backend", "backend-pod")
        assert pod is not None
        assert len(pod.containers) == 1
        assert pod.containers[0].name == "backend"
        assert len(pod.containers[0].ports) == 1
        assert pod.containers[0].ports[0].container_port == 8080
