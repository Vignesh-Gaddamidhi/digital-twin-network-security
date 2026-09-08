# Day 46: Network Utilisation & Connection State Architecture

## 1. Network Activity Metrics
For each network endpoint, dynamic interface consumption is modeled across five core fields:
- `networkUtilisation`: Normalized saturation factor ($0.0 \le x \le 100.0\%$).
- `bytesSent` / `bytesReceived`: Monotonically increasing throughput counters.
- `packetsSent` / `packetsReceived`: Packet frame counters.

## 2. Dynamic Connection Session Lifecycle
Individual Layer 4 conversations are tracked with temporal states:
- `ACTIVE`: Session is open and transmitting data.
- `CLOSED`: Graceful session termination (`TCP FIN`/`RST`).
- `FAILED`: Abrupt session disruption (`TCP TIMEOUT`, `SYN FLOOD DROP`, `CONN_REFUSED`).

## 3. Structural Graph vs. Operational Edge State
In Phase 5, edges represent structural reachability. Day 46 binds operational conditions to these edges:
- Structural Edge: `Client -> Web -> Database` remains present in the graph topology.
- Operational Edge: If `Web -> Database` enters `FAILED`, reachability queries evaluate to `UNREACHABLE` without removing the edge from the graph.