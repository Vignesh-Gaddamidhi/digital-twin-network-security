# Day 39: Path Finding & Network Reachability Engine

## 1. Reachability Spectrum
In the Network Digital Twin, reachability is evaluated across two levels:
1. **Topological Reachability:** Is there a valid geometric sequence of links connecting vertex $A$ to vertex $B$? Solved via unweighted Breadth-First Search (BFS) or Dijkstra shortest path.
2. **Security-Constrained Reachability:** Can network traffic actually pass from $A$ to $B$ given current operating conditions?
   - Source and destination devices must be `ONLINE`.
   - All intermediary hops must be `ONLINE`.
   - All traversed links must be `ACTIVE`.
   - Inter-zone transitions must comply with active `FirewallRule` definitions for the given protocol and destination port.

## 2. Core API Methods
- `isReachable(source, destination, protocol, port)`: Boolean check returning whether traffic can reach the target under security constraints.
- `findPath(source, destination)`: Returns the raw topological path using BFS.
- `getShortestPath(source, destination, weight_metric)`: Returns the optimal path based on latency or cost.
- `getNeighbors(device_id)`: Enumerates immediate 1-hop reachable peers.