# OVN-Kubernetes Troubleshooting Guide

## OVN-Kubernetes Concepts

### Logical Switches
Each Kubernetes node maps to an OVN logical switch. The switch represents the
pod network on that node and uses the node's pod CIDR subnet (e.g.
`10.244.1.0/24`). Every pod gets a logical switch port on its node's switch.

### Logical Switch Ports
Each pod interface is represented as a logical switch port (LSP) with a MAC
address and IP from the node's pod CIDR. OVN-NetDiag maps pod IPs to LSP names
to correlate Kubernetes pod state with OVN state.

### Port Groups
OVN-Kubernetes creates port groups to represent sets of pods that share the
same NetworkPolicy rules. When a NetworkPolicy selects pods via a
`podSelector`, OVN-Kubernetes creates a port group containing those pods'
LSP names. ACLs are then attached to the port group.

### ACLs (Access Control Lists)
ACLs are the OVN enforcement mechanism for NetworkPolicies. Each ACL has:
- **Direction**: `to-lport` (ingress) or `from-lport` (egress)
- **Priority**: Higher priority wins. OVN-Kubernetes typically uses 1000+
  for policy ACLs.
- **Match**: An OVN match expression (e.g. `ip4.src == 10.244.1.5 && tcp.dst == 8080`)
- **Action**: `allow`, `allow-related`, `drop`, or `reject`

A default-deny NetworkPolicy creates a low-priority `drop` ACL with match `ip`
on the pod's port group. An allow rule creates a higher-priority `allow-related`
ACL with a specific match expression.

### Logical Routers
OVN uses a single logical router (typically `ovn-cluster`) to route traffic
between logical switches (nodes). The router has ports connected to each
logical switch.

### Logical Flows
The OVN Southbound database contains logical flows that represent the
distributed router and switch pipeline. These flows determine how packets are
forwarded, routed, or dropped across the overlay network.

### OpenFlow Flows (OVS)
On each node, OVN compiles logical flows into OpenFlow rules on the
integration bridge (`br-int`). `ovs-ofctl dump-flows br-int` shows the
actual forwarding rules. A `drop` action here means packets are silently
discarded; an `output:N` action sends packets to port N.

## Troubleshooting Workflow

### Step 1: Identify the Pods
```
ovn-netdiag pod-info --namespace <ns> --pod <pod> --mock
```
Confirm both source and destination pods exist, are Running, and have valid IP
addresses. Note their node assignments and labels.

### Step 2: Run the Full Diagnostic
```
ovn-netdiag diagnose --namespace <src-ns> --source <src-pod> \
  --destination <dst-pod> --port <port> --mock
```
Review each layer's verdict:
- **KUBERNETES**: Are both pods healthy?
- **NETWORK POLICY**: Do any policies allow or deny this traffic?
- **OVN ACL**: Do OVN ACLs allow or drop this traffic?
- **OVS FLOW**: Do OpenFlow rules forward or drop this traffic?
- **TCP CONNECTIVITY**: Can we actually establish a connection?

### Step 3: Interpret the Diagnosis

| NetworkPolicy | OVN ACL | OVS Flow | Connectivity | Likely Cause |
|---|---|---|---|---|
| PASS | PASS | PASS | PASS | No issues — traffic works |
| DENIED | DROP | DROP | FAILED | NetworkPolicy blocking traffic |
| PASS | DROP | DROP | FAILED | OVN ACL misconfiguration |
| PASS | PASS | DROP | FAILED | OVS flow issue |
| PASS | PASS | PASS | FAILED | Application or node networking |
| DENIED | PASS | PASS | PASS | Policy not enforced (misconfig) |

### Step 4: Investigate OVN State
```
ovn-netdiag ovn-info --mock
```
Check:
- Does the destination pod have a logical switch port?
- Which port group does it belong to?
- Are there `drop` ACLs on that port group?
- Is there an `allow-related` ACL with higher priority matching the source?

### Step 5: Investigate OVS Flows
Look for flows matching the destination IP and port:
- A `drop` action means traffic is being discarded at the OVS level
- An `output` action means traffic is being forwarded
- Priority determines which flow wins when multiple match

## Common Issues

### Default Deny Without Allow Rule
A namespace has a default-deny NetworkPolicy but no allow rule for the source
pod's traffic. The diagnostic will show:
- NetworkPolicy: DENIED
- OVN ACL: DROP
- Connectivity: FAILED

**Fix**: Add an ingress NetworkPolicy rule allowing the source pod's traffic.

### Pod Not in OVN
The pod exists in Kubernetes but has no logical switch port in OVN. This
indicates the CNI plugin has not processed the pod yet.

**Fix**: Restart the ovn-kubernetes node controller or check OVN Northbound
database connectivity.

### OVN ACL vs NetworkPolicy Mismatch
The NetworkPolicy allows traffic but OVN ACLs drop it. This can happen if
OVN-Kubernetes has not synchronized the NetworkPolicy to OVN ACLs.

**Fix**: Restart the ovn-kubernetes network policy controller.

### Cross-Node Routing Failure
Pods on different nodes cannot communicate despite all policies allowing
traffic. The issue may be with the OVN logical router or underlay network.

**Fix**: Check logical flows on the `ovn-cluster` router and verify
Geneve tunnel connectivity between nodes.
