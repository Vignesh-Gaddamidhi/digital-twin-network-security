# Day 137: Attack Path Discovery & Reachability Analysis Engine

## 1. Graph Traversal with Security Constraints
Path exploration executes bounded directed traversals over the security-aware Digital Twin graph:
- **Shortest Path (BFS):** Discovers the minimum-hop traversal route from source to target.
- **All Feasible Paths (Bounded DFS):** Finds all alternate routing paths within configurable depth bounds.

## 2. Guardrails Against Pathological Graphs
To guarantee real-time execution (<20 ms) in dense topologies, traversals enforce:
$$\text{Depth} \le \text{maxDepth} \quad \land \quad |\text{Paths}| \le \text{maxPaths} \quad \land \quad v \notin \text{VisitedPath}$$

## 3. Preservation of Blocked & Partial Trajectories
Defenders require intelligence regarding where controls succeed and fail:
- A `BLOCKED` path identifies active firewall defense enforcement.
- A `PARTIALLY_REACHABLE` path identifies how deep an adversary can penetrate before encountering an isolation or segmentation barrier (`blockedAt`).