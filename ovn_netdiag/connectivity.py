"""TCP connectivity tester.

Uses ``socket.create_connection`` and ``time.perf_counter`` to test
real TCP reachability. In mock mode, returns deterministic results
based on the mock cluster scenario.
"""

from __future__ import annotations

import socket
import time

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.logging_config import get_logger
from ovn_netdiag.models import ConnectivityResult

logger = get_logger("connectivity")


# Mock connectivity scenarios: (source_namespace, source_name, dest_ip, port) -> reachable
_MOCK_SCENARIOS: dict[tuple[str, str, str, int], bool] = {
    # frontend -> backend on 8080: reachable (NetworkPolicy allows it)
    ("frontend", "frontend-pod", "10.244.2.10", 8080): True,
    # frontend -> restricted on 3306: unreachable (default deny)
    ("frontend", "frontend-pod", "10.244.2.20", 3306): False,
    # frontend -> db on 5432: unreachable (no ingress policy on db, but no allow either)
    ("frontend", "frontend-pod", "10.244.0.15", 5432): False,
    # backend -> db on 5432: reachable (db has egress policy allowing backend)
    ("backend", "backend-pod", "10.244.0.15", 5432): True,
}


class ConnectivityTester:
    """Test TCP connectivity between source and destination."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def test(
        self,
        source: str,
        target: str,
        destination_ip: str,
        port: int,
        protocol: str = "tcp",
    ) -> ConnectivityResult:
        """Run a connectivity test.

        Args:
            source: Source identifier (e.g. ``namespace/pod-name``).
            target: Target identifier (e.g. ``namespace/pod-name``).
            destination_ip: IP address to connect to.
            port: TCP port.
            protocol: Protocol (only ``tcp`` is supported for live tests).

        Returns:
            ConnectivityResult with reachability, latency, and error info.
        """
        if self.config.is_mock:
            return self._mock_test(source, target, destination_ip, port, protocol)
        return self._real_test(source, target, destination_ip, port, protocol)

    # ------------------------------------------------------------------
    # Mock implementation
    # ------------------------------------------------------------------

    def _mock_test(
        self,
        source: str,
        target: str,
        destination_ip: str,
        port: int,
        protocol: str,
    ) -> ConnectivityResult:
        # Parse source "namespace/pod-name"
        source_parts = source.split("/", 1)
        source_ns = source_parts[0] if len(source_parts) == 2 else ""
        source_name = source_parts[1] if len(source_parts) == 2 else source

        key = (source_ns, source_name, destination_ip, port)
        reachable = _MOCK_SCENARIOS.get(key, False)

        if reachable:
            return ConnectivityResult(
                source=source,
                target=target,
                destination_ip=destination_ip,
                port=port,
                protocol=protocol,
                reachable=True,
                latency_ms=0.42,
                error=None,
            )
        return ConnectivityResult(
            source=source,
            target=target,
            destination_ip=destination_ip,
            port=port,
            protocol=protocol,
            reachable=False,
            latency_ms=None,
            error="Connection refused (MOCK)",
        )

    # ------------------------------------------------------------------
    # Real implementation
    # ------------------------------------------------------------------

    def _real_test(
        self,
        source: str,
        target: str,
        destination_ip: str,
        port: int,
        protocol: str,
    ) -> ConnectivityResult:
        if protocol.lower() != "tcp":
            return ConnectivityResult(
                source=source,
                target=target,
                destination_ip=destination_ip,
                port=port,
                protocol=protocol,
                reachable=False,
                latency_ms=None,
                error=f"Protocol '{protocol}' not supported for live connectivity test",
            )

        logger.debug("Testing TCP connection to %s:%d", destination_ip, port)
        start = time.perf_counter()
        try:
            with socket.create_connection(
                (destination_ip, port),
                timeout=self.config.connect_timeout,
            ) as _sock:
                elapsed = (time.perf_counter() - start) * 1000
                return ConnectivityResult(
                    source=source,
                    target=target,
                    destination_ip=destination_ip,
                    port=port,
                    protocol=protocol,
                    reachable=True,
                    latency_ms=round(elapsed, 3),
                    error=None,
                )
        except socket.timeout:
            elapsed = (time.perf_counter() - start) * 1000
            return ConnectivityResult(
                source=source,
                target=target,
                destination_ip=destination_ip,
                port=port,
                protocol=protocol,
                reachable=False,
                latency_ms=round(elapsed, 3),
                error="Connection timed out",
            )
        except ConnectionRefusedError:
            return ConnectivityResult(
                source=source,
                target=target,
                destination_ip=destination_ip,
                port=port,
                protocol=protocol,
                reachable=False,
                latency_ms=None,
                error="Connection refused",
            )
        except OSError as exc:
            return ConnectivityResult(
                source=source,
                target=target,
                destination_ip=destination_ip,
                port=port,
                protocol=protocol,
                reachable=False,
                latency_ms=None,
                error=str(exc),
            )
