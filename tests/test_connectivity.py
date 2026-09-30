"""Tests for the TCP connectivity tester."""

from __future__ import annotations

import socket

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.connectivity import ConnectivityTester
from ovn_netdiag.models import ConnectivityResult


class TestConnectivityMock:
    """Test ConnectivityTester in mock mode."""

    def test_mock_reachable_frontend_to_backend(self, mock_config: RuntimeConfig) -> None:
        tester = ConnectivityTester(mock_config)
        result = tester.test(
            source="frontend/frontend-pod",
            target="backend/backend-pod",
            destination_ip="10.244.2.10",
            port=8080,
            protocol="tcp",
        )
        assert isinstance(result, ConnectivityResult)
        assert result.reachable is True
        assert result.latency_ms is not None
        assert result.error is None
        assert result.status == "reachable"

    def test_mock_unreachable_frontend_to_restricted(self, mock_config: RuntimeConfig) -> None:
        tester = ConnectivityTester(mock_config)
        result = tester.test(
            source="frontend/frontend-pod",
            target="restricted/blocked-pod",
            destination_ip="10.244.2.20",
            port=3306,
            protocol="tcp",
        )
        assert result.reachable is False
        assert result.error is not None
        assert result.status == "unreachable"

    def test_mock_unreachable_unknown_scenario(self, mock_config: RuntimeConfig) -> None:
        tester = ConnectivityTester(mock_config)
        result = tester.test(
            source="unknown/unknown-pod",
            target="unknown/unknown-pod",
            destination_ip="1.1.1.1",
            port=1234,
            protocol="tcp",
        )
        assert result.reachable is False

    def test_result_fields(self, mock_config: RuntimeConfig) -> None:
        tester = ConnectivityTester(mock_config)
        result = tester.test(
            source="frontend/frontend-pod",
            target="backend/backend-pod",
            destination_ip="10.244.2.10",
            port=8080,
        )
        assert result.source == "frontend/frontend-pod"
        assert result.target == "backend/backend-pod"
        assert result.destination_ip == "10.244.2.10"
        assert result.port == 8080
        assert result.protocol == "tcp"


class TestConnectivityReal:
    """Test ConnectivityTester in real mode against localhost."""

    def test_real_connect_to_echo_port(self, real_config: RuntimeConfig) -> None:
        """Start a temporary TCP server and test connectivity to it."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        tester = ConnectivityTester(real_config)
        result = tester.test(
            source="test/src",
            target="test/dst",
            destination_ip="127.0.0.1",
            port=port,
            protocol="tcp",
        )
        srv.close()
        assert result.reachable is True
        assert result.latency_ms is not None
        assert result.latency_ms >= 0

    def test_real_connect_refused(self, real_config: RuntimeConfig) -> None:
        """Test connecting to a port that should be closed."""
        # Use a port unlikely to be in use
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()

        tester = ConnectivityTester(real_config)
        result = tester.test(
            source="test/src",
            target="test/dst",
            destination_ip="127.0.0.1",
            port=port,
            protocol="tcp",
        )
        assert result.reachable is False
        assert result.error is not None

    def test_real_unsupported_protocol(self, real_config: RuntimeConfig) -> None:
        tester = ConnectivityTester(real_config)
        result = tester.test(
            source="test/src",
            target="test/dst",
            destination_ip="127.0.0.1",
            port=8080,
            protocol="udp",
        )
        assert result.reachable is False
        assert "not supported" in result.error
