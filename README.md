# OVN-NetDiag

**OVN-Kubernetes Network Diagnostics Tool**

Diagnose why TCP traffic between two Kubernetes Pods is reachable, blocked, or
unreachable by correlating Kubernetes resources, NetworkPolicies, OVN
Northbound/Southbound state, Open vSwitch flows, and real TCP connectivity.

## Project Purpose

When pod-to-pod communication fails in an OVN-Kubernetes cluster, the cause
could be a NetworkPolicy, an OVN ACL, an OVS flow, a routing issue, or an
application-level problem. OVN-NetDiag collects evidence from all these layers
in a single command and produces a clear diagnosis with a confidence level.

## Architecture

```
CLI → DiagnosticEngine → { KubernetesInspector, PolicyAnalyzer,
                            OvnInspector, OvsInspector, ConnectivityTester }
                         → Reporter → stdout (text or JSON)
```

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing, command dispatch |
| `config.py` | Runtime configuration and constants |
| `models.py` | Typed data structures (frozen dataclasses) |
| `mock_data.py` | Mock cluster data provider |
| `kubernetes_inspector.py` | Read-only K8s API inspection |
| `policy_analyzer.py` | NetworkPolicy ingress/egress analysis |
| `ovn_inspector.py` | OVN NB/SB state via `ovn-nbctl`/`ovn-sbctl` |
| `ovs_inspector.py` | OVS bridges and flows via `ovs-ofctl` |
| `connectivity.py` | TCP connectivity test via `socket` |
| `diagnostic_engine.py` | Correlates all layers into a diagnosis |
| `reporter.py` | Text and JSON output formatting |
| `logging_config.py` | Logging configuration |

See [docs/architecture.md](docs/architecture.md) for details.

## Installation

```bash
cd ovn-netdiag
pip install -e .
```

For development (includes pytest):

```bash
pip install -e ".[dev]"
```

## CLI Examples

### Diagnose pod-to-pod connectivity
```bash
ovn-netdiag diagnose \
  --namespace frontend \
  --source frontend-pod \
  --destination backend-pod \
  --port 8080 \
  --protocol tcp \
  --mock
```

### JSON output
```bash
ovn-netdiag diagnose \
  --namespace frontend \
  --source frontend-pod \
  --destination backend-pod \
  --port 8080 \
  --mock --json
```

### Cluster overview
```bash
ovn-netdiag cluster-info --mock
```

### Pod details
```bash
ovn-netdiag pod-info --namespace frontend --pod frontend-pod --mock
```

### OVN state
```bash
ovn-netdiag ovn-info --mock
```

### Verbose logging
```bash
ovn-netdiag diagnose --namespace frontend --source frontend-pod \
  --destination backend-pod --port 8080 --mock --verbose
```

### Run as a module
```bash
python -m ovn_netdiag --help
```

## Mock Mode

OVN-NetDiag works without a Kubernetes or OVN cluster using `--mock`. Mock data
is loaded from `examples/mock_cluster.json` and includes realistic:

- 4 Pods across 3 nodes and 4 namespaces
- 2 Services with selectors and endpoints
- 4 NetworkPolicies (default-deny and allow rules)
- OVN logical switches, ports, port groups, ACLs, and logical flows
- OVS bridges and OpenFlow flows
- Deterministic connectivity results

Mock output is clearly labeled `MODE: MOCK` so it is never confused with real
cluster data.

### Mock Cluster Scenario

| Source | Destination | Port | Expected |
|---|---|---|---|
| frontend/frontend-pod | backend/backend-pod | 8080 | Allowed, reachable |
| frontend/frontend-pod | restricted/blocked-pod | 3306 | Denied (default-deny), unreachable |
| backend/backend-pod | database/db-pod | 5432 | Allowed (egress policy), reachable |

## OVN-Kubernetes Concepts

- **Logical Switches**: Each node maps to an OVN logical switch using the node's pod CIDR.
- **Logical Switch Ports**: Each pod interface is an LSP with a MAC and IP.
- **Port Groups**: Sets of LSPs sharing NetworkPolicy rules.
- **ACLs**: OVN enforcement for NetworkPolicies — `allow`, `allow-related`, `drop`, `reject`.
- **Logical Routers**: Route traffic between logical switches (nodes).
- **Logical Flows**: Southbound DB pipeline representing router/switch logic.
- **OpenFlow Flows**: Compiled rules on `br-int` that actually forward or drop packets.

See [docs/ovn-troubleshooting.md](docs/ovn-troubleshooting.md) for a detailed
troubleshooting guide.

## Troubleshooting Workflow

1. **Identify pods**: `ovn-netdiag pod-info` — confirm both pods exist and are Running.
2. **Run diagnostic**: `ovn-netdiag diagnose` — review each layer's verdict.
3. **Check policies**: Look at the NETWORK POLICY verdict for allow/deny.
4. **Check OVN**: `ovn-netdiag ovn-info` — look for drop ACLs on the destination's port group.
5. **Check OVS**: Look for drop flows matching the destination IP.
6. **Correlate**: Use the diagnosis and confidence to identify the root cause.

## Safety / Read-Only Design

- **Strictly read-only**: Never modifies Kubernetes, OVN, or OVS state.
- **No `shell=True`**: All subprocess calls use argument lists.
- **Timeouts**: All subprocess calls have configurable timeouts.
- **No arbitrary commands**: User input is never passed as a shell command.
- **Mock mode**: Requires no cluster access at all.

## Limitations

- TCP connectivity test runs from the machine executing the tool, not from
  inside the source pod. For in-cluster testing, use `kubectl exec` with the
  tool running inside a pod.
- Real mode requires `ovn-nbctl`, `ovn-sbctl`, and `ovs-ofctl` to be installed
  and accessible on the host.
- Real mode requires a valid kubeconfig or in-cluster service account.
- UDP connectivity is not tested live (only TCP via `socket.create_connection`).
- EndpointSlices are supported through the Endpoints API; direct EndpointSlice
  listing depends on the Kubernetes client version.
- The tool does not modify any resources — it cannot fix issues, only diagnose them.

## Running Tests

```bash
cd ovn-netdiag
pip install -e ".[dev]"
pytest
```

Tests do not require a real Kubernetes or OVN cluster — all tests use mock data
or local TCP sockets.
