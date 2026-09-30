# Architecture

## Overview

OVN-NetDiag is a read-only diagnostic tool that correlates data from five layers
to determine why TCP traffic between two Kubernetes Pods is reachable, blocked,
or unreachable.

```
┌──────────────────────────────────────────────────┐
│                    CLI (cli.py)                   │
│   diagnose | cluster-info | pod-info | ovn-info  │
└──────────────────────┬───────────────────────────┘
                       │
              ┌────────▼────────┐
              │ DiagnosticEngine │
              │  (correlator)   │
              └────────┬────────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
     ┌────▼────┐ ┌────▼────┐ ┌────▼────┐
     │  K8s    │ │ Policy  │ │  OVN    │
     │Inspector│ │Analyzer │ │Inspector│
     └────┬────┘ └────┬────┘ └────┬────┘
          │            │            │
     ┌────▼────┐       │       ┌────▼────┐
     │  OVS    │       │       │  OVN    │
     │Inspector│       │       │  SB/NB  │
     └────┬────┘       │       └─────────┘
          │            │
     ┌────▼────┐ ┌────▼────┐
     │Connect. │ │ Models  │
     │ Tester  │ │ (types) │
     └─────────┘ └─────────┘
```

## Modules

### cli.py
Entry point. Uses `argparse` to parse four subcommands and shared options
(`--mock`, `--json`, `--verbose`, `--namespace`, `--port`, etc.). Builds a
`RuntimeConfig` and dispatches to the `DiagnosticEngine`.

### config.py
Defines `RuntimeConfig`, a dataclass holding all runtime options including
mode (`MOCK`/`REAL`), timeouts, and target parameters. Also defines constant
strings for verdicts and confidence levels.

### models.py
All typed data structures as frozen dataclasses:
- **Kubernetes**: `PodInfo`, `ServiceInfo`, `EndpointInfo`, `NodeInfo`
- **NetworkPolicy**: `NetworkPolicyInfo`, `NetworkPolicyRule`, `NetworkPolicyPort`
- **OVN**: `OvnState`, `OvnACL`, `OvnLogicalSwitch`, `OvnLogicalSwitchPort`, `OvnPortGroup`, `OvnLogicalRouter`, `OvnLogicalFlow`
- **OVS**: `OvsState`, `OvsBridge`, `OvsFlow`
- **Connectivity**: `ConnectivityResult`
- **Report**: `CheckResult`, `DiagnosticReport`

### mock_data.py
`MockDataProvider` loads `examples/mock_cluster.json` and converts raw JSON
into typed model objects. Provides lookup helpers (`find_pod`, `pods_in_namespace`,
etc.) used by all inspectors when running in mock mode.

### kubernetes_inspector.py
`KubernetesInspector` collects Pods, Services, Endpoints, Nodes, and
NetworkPolicies into a `KubernetesSnapshot`. In real mode it uses the
Kubernetes Python client (`kubernetes` package). In mock mode it delegates to
`MockDataProvider`. All API calls are read-only.

### policy_analyzer.py
`PolicyAnalyzer` evaluates ingress and egress NetworkPolicies to determine
whether traffic from a source pod to a destination pod on a given port and
protocol is allowed, denied, or uncertain. It checks podSelector,
namespaceSelector, ipBlock, and port matching. Returns a `PolicyVerdict` with
confidence level (`CONFIRMED`, `LIKELY`, `UNKNOWN`).

### ovn_inspector.py
`OvnInspector` queries OVN Northbound and Southbound databases via safe
`subprocess` calls to `ovn-nbctl` and `ovn-sbctl`. Inspects logical switches,
logical switch ports, port groups, ACLs, logical routers, and logical flows.
Includes parsers for real command output. Never invents data in real mode.

### ovs_inspector.py
`OvsInspector` queries Open vSwitch via `ovs-ofctl` and `ovs-vsctl` subprocess
calls. Inspects bridges and OpenFlow flow tables. Includes a flow-line parser
that extracts cookie, priority, table, match, and actions.

### connectivity.py
`ConnectivityTester` performs TCP connectivity tests using
`socket.create_connection()` and `time.perf_counter()`. Returns
`ConnectivityResult` with reachable/unreachable status, latency in
milliseconds, and error reason. In mock mode, results are deterministic based
on the mock cluster scenario.

### diagnostic_engine.py
`DiagnosticEngine` orchestrates the full diagnostic workflow:
1. Collect Kubernetes resources
2. Locate source and destination pods
3. Run individual checks (Kubernetes, NetworkPolicy, OVN, OVS, Connectivity)
4. Correlate all results into a final diagnosis with confidence

The correlation logic combines verdicts from all layers. It only reports
`CONFIRMED` when evidence from multiple layers supports the conclusion.

### reporter.py
`Reporter` formats `DiagnosticReport` objects for output. Supports human-readable
text and JSON. Also formats cluster-info, pod-info, and ovn-info outputs.

### logging_config.py
Configures the `ovn_netdiag` logger hierarchy. Verbose mode sets DEBUG level;
default is INFO. Logs go to stderr so stdout remains clean for JSON output.

## Data Flow

1. CLI parses arguments → `RuntimeConfig`
2. `DiagnosticEngine` created with config
3. Engine calls each inspector (mock or real)
4. `PolicyAnalyzer` evaluates collected NetworkPolicies
5. `ConnectivityTester` runs TCP probe
6. Engine correlates all `CheckResult` objects
7. `Reporter` formats the `DiagnosticReport`
8. CLI prints text or JSON to stdout

## Safety Design

- All Kubernetes API calls are read-only (list, read — never create, update, delete)
- All OVN/OVS commands use `subprocess.run` with argument lists (never `shell=True`)
- All subprocess calls have timeouts
- No user input is passed unsanitized to subprocess
- Mock mode requires no cluster access
