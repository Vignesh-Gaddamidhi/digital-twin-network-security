# Day 178: Attack Simulation, Risk Analysis & Attack Paths

## 1. Module Workflow Integration
Day 178 binds synthetic scenario execution, mathematical risk decomposition, and graph traversal analysis into a closed operational loop:

[Attack Simulation Sandbox] ──> [Synthetic Traffic Stream] ──> [Dynamic Risk Decomposer]
│
▼
[Safe Response Playbook] <──[Mitigate Path]── [Attack Path Graph] <──[Risk Exposure]


## 2. Canonical Factor Breakdown
The Risk view exposes the $P \times C \times V \times I$ calculation:
$$\text{Risk Score} = P_{\text{threat}} \times C_{\text{asset}} \times V_{\text{vuln}} \times I_{\text{impact}} \times 100$$

## 3. Attack Path Lifecycle States
- `POSSIBLE`: Discovered graph path based on network topology.
- `ACTIVE (SIMULATED)`: Currently traversed during an active simulation run.
- `BLOCKED`: Ingress/egress edge severed via `ISOLATE_DEVICE` or `BLOCK_CONNECTION`.
- `MITIGATED`: Vulnerability patched or target service disabled.
- `HISTORICAL`: Previous traversed run preserved in audit history.
- `UNVERIFIED`: Graph edge without verified live flow reachability.