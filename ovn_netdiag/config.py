"""Configuration and runtime constants for OVN-NetDiag."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT: float = 5.0
DEFAULT_CONNECT_TIMEOUT: float = 3.0
DEFAULT_OVN_TIMEOUT: float = 10.0
DEFAULT_OVS_TIMEOUT: float = 10.0
DEFAULT_K8S_TIMEOUT: float = 10.0

MOCK_DATA_FILE: str = "mock_cluster.json"

# Confidence levels
CONFIDENCE_CONFIRMED: str = "CONFIRMED"
CONFIDENCE_LIKELY: str = "LIKELY"
CONFIDENCE_UNKNOWN: str = "UNKNOWN"

# Verdicts
VERDICT_PASS: str = "PASS"
VERDICT_DENIED: str = "DENIED"
VERDICT_UNKNOWN: str = "UNKNOWN"
VERDICT_FAILED: str = "FAILED"

# Modes
MODE_REAL: str = "REAL"
MODE_MOCK: str = "MOCK"


@dataclass
class RuntimeConfig:
    """Holds all runtime options passed from the CLI."""

    namespace: str | None = None
    source: str | None = None
    destination: str | None = None
    pod: str | None = None
    port: int | None = None
    protocol: str = "tcp"
    json_output: bool = False
    verbose: bool = False
    mock: bool = False
    mock_data_path: str | None = None
    kubeconfig: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    ovn_timeout: float = DEFAULT_OVN_TIMEOUT
    ovs_timeout: float = DEFAULT_OVS_TIMEOUT
    k8s_timeout: float = DEFAULT_K8S_TIMEOUT
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def mode(self) -> str:
        """Return the current operational mode string."""
        return MODE_MOCK if self.mock else MODE_REAL

    @property
    def is_mock(self) -> bool:
        return self.mock

    @property
    def is_real(self) -> bool:
        return not self.mock
