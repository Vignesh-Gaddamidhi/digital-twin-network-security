# Day 134: Attack Path Analysis Fundamentals & Graph Model

## 1. Network Path vs. Attack Path
- **Network Path (Infrastructure Topology):** Describes Layer 2/3 packet forwarding routes (e.g. `Client -> Switch -> Router -> Firewall -> Server`).
- **Attack Path (Threat Exposure Trajectory):** Describes directed, exploitable service relationships governed by:
  $$\text{Attack Edge } (u \to v) \iff \text{Reachable}(u, v) \land \text{PortOpen}(v, p) \land \neg \text{BlockedByControl}(u, v, p)$$

## 2. Directed Asymmetry Invariant
In network security, reachability is strictly asymmetric:
$$\text{Edge}(A \to B) \centernot\implies \text{Edge}(B \to A)$$
An external client may reach a DMZ Web Server on port 443, while the DMZ server is prevented by egress firewall filtering from initiating connections back to the client subnet.

## 3. Path Status States
- `POSSIBLE`: Path satisfies all reachability and service exposure constraints.
- `BLOCKED`: Firewall rule or ACL explicitly severs at least one intermediate edge.
- `PARTIALLY_REACHABLE`: Route reachable up to intermediate node, but terminal target blocked.
- `UNVERIFIED`: Path structurally valid, but active credentials/exploits unconfirmed.
- `ACTIVE_SIMULATION`: Real-time traffic actively traversing nodes in Digital Twin simulation.
- `COMPLETED`: Threat reached target node in simulated scenario.
- `INVALID`: Disconnected or broken graph topology.