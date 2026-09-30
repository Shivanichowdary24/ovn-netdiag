"""Data models for OVN-NetDiag.

All data structures used across inspectors and the diagnostic engine
are defined here as frozen dataclasses for immutability and clarity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Kubernetes models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContainerPort:
    container_port: int
    protocol: str = "TCP"


@dataclass(frozen=True)
class Container:
    name: str
    ports: tuple[ContainerPort, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PodInfo:
    name: str
    namespace: str
    ip: str
    node: str
    labels: dict[str, str]
    containers: tuple[Container, ...]
    phase: str = "Running"

    def matches_selector(self, selector: dict[str, str]) -> bool:
        """Return True if this pod's labels match the given selector."""
        if not selector:
            return True
        return all(self.labels.get(k) == v for k, v in selector.items())


@dataclass(frozen=True)
class ServicePort:
    port: int
    target_port: int
    protocol: str = "TCP"


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    namespace: str
    cluster_ip: str
    ports: tuple[ServicePort, ...]
    selector: dict[str, str]
    type: str = "ClusterIP"


@dataclass(frozen=True)
class EndpointInfo:
    name: str
    namespace: str
    addresses: tuple[str, ...]
    ports: tuple[ServicePort, ...]
    ready: bool = True


@dataclass(frozen=True)
class NodeInfo:
    name: str
    pod_cidr: str
    addresses: tuple[str, ...]
    status: str = "Ready"


# ---------------------------------------------------------------------------
# NetworkPolicy models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkPolicyPort:
    port: int | None
    protocol: str = "TCP"


@dataclass(frozen=True)
class NetworkPolicyRule:
    """A single ingress or egress rule in a NetworkPolicy."""

    pod_selector: dict[str, str] = field(default_factory=dict)
    namespace_selector: dict[str, str] = field(default_factory=dict)
    ip_blocks: tuple[str, ...] = field(default_factory=tuple)
    ports: tuple[NetworkPolicyPort, ...] = field(default_factory=tuple)

    @property
    def allows_all_pods(self) -> bool:
        """An empty pod_selector and empty namespace_selector means all pods."""
        return not self.pod_selector and not self.namespace_selector and not self.ip_blocks

    @property
    def allows_all_ports(self) -> bool:
        """No port restrictions means all ports are allowed."""
        return len(self.ports) == 0


@dataclass(frozen=True)
class NetworkPolicyInfo:
    name: str
    namespace: str
    types: tuple[str, ...]
    pod_selector: dict[str, str]
    ingress_rules: tuple[NetworkPolicyRule, ...] | None = None
    egress_rules: tuple[NetworkPolicyRule, ...] | None = None

    @property
    def has_ingress(self) -> bool:
        return "Ingress" in self.types

    @property
    def has_egress(self) -> bool:
        return "Egress" in self.types

    @property
    def is_default_deny_ingress(self) -> bool:
        """Default-deny ingress: has Ingress type but no ingress rules."""
        return self.has_ingress and (self.ingress_rules is None or len(self.ingress_rules) == 0)

    @property
    def is_default_deny_egress(self) -> bool:
        """Default-deny egress: has Egress type but no egress rules."""
        return self.has_egress and (self.egress_rules is None or len(self.egress_rules) == 0)


# ---------------------------------------------------------------------------
# OVN models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OvnLogicalSwitch:
    name: str
    subnet: str = ""


@dataclass(frozen=True)
class OvnLogicalSwitchPort:
    name: str
    switch: str
    addresses: tuple[str, ...] = field(default_factory=tuple)
    type: str = ""


@dataclass(frozen=True)
class OvnPortGroup:
    name: str
    ports: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class OvnACL:
    uuid: str
    port_group: str
    direction: str  # to-lport | from-lport
    priority: int
    match: str
    action: str  # allow-related | allow | drop | reject
    log: bool = False


@dataclass(frozen=True)
class OvnLogicalRouter:
    name: str
    ports: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class OvnLogicalFlow:
    uuid: str
    router: str
    match: str
    actions: str
    priority: int = 100


@dataclass
class OvnState:
    logical_switches: list[OvnLogicalSwitch] = field(default_factory=list)
    logical_switch_ports: list[OvnLogicalSwitchPort] = field(default_factory=list)
    port_groups: list[OvnPortGroup] = field(default_factory=list)
    acls: list[OvnACL] = field(default_factory=list)
    logical_routers: list[OvnLogicalRouter] = field(default_factory=list)
    logical_flows: list[OvnLogicalFlow] = field(default_factory=list)


# ---------------------------------------------------------------------------
# OVS models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OvsBridge:
    name: str
    datapath_id: str = ""
    ports: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class OvsFlow:
    cookie: str = "0x0"
    priority: int = 0
    table: int = 0
    match: str = ""
    actions: str = ""

    @property
    def is_drop(self) -> bool:
        return self.actions.strip().lower() == "drop"

    @property
    def is_normal(self) -> bool:
        return self.actions.strip().upper() == "NORMAL"


@dataclass
class OvsState:
    bridges: list[OvsBridge] = field(default_factory=list)
    flows: list[OvsFlow] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Connectivity models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectivityResult:
    source: str
    target: str
    destination_ip: str
    port: int
    protocol: str
    reachable: bool
    latency_ms: float | None
    error: str | None = None

    @property
    def status(self) -> str:
        return "reachable" if self.reachable else "unreachable"


# ---------------------------------------------------------------------------
# Diagnostic result models
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Result of a single diagnostic check."""

    name: str
    verdict: str  # PASS | DENIED | UNKNOWN | FAILED
    confidence: str  # CONFIRMED | LIKELY | UNKNOWN
    details: str = ""
    evidence: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiagnosticReport:
    """Full diagnostic report combining all check results."""

    source_pod: str
    destination_pod: str
    destination_ip: str
    port: int
    protocol: str
    mode: str = "REAL"
    checks: list[CheckResult] = field(default_factory=list)
    diagnosis: str = ""
    confidence: str = "UNKNOWN"

    def add_check(self, result: CheckResult) -> None:
        self.checks.append(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "source_pod": self.source_pod,
            "destination_pod": self.destination_pod,
            "destination_ip": self.destination_ip,
            "port": self.port,
            "protocol": self.protocol,
            "checks": [
                {
                    "name": c.name,
                    "verdict": c.verdict,
                    "confidence": c.confidence,
                    "details": c.details,
                    "evidence": c.evidence,
                    "data": c.data,
                }
                for c in self.checks
            ],
            "diagnosis": self.diagnosis,
            "confidence": self.confidence,
        }
