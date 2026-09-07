# Day 24: Graph-Theoretic Principles for Attack Path Modeling

## 1. Graph Semantics
The network is modeled as a directed multigraph:
$$\mathcal{G} = (\mathcal{V}, \mathcal{E})$$
Where:
- $\mathcal{V}$ is the set of all devices (hosts, switches, routers).
- $\mathcal{E}$ is the multiset of directed edges $(u, v, k)$ annotated with connection type, exposure, and latency.

## 2. Algorithms
- **Dijkstra Shortest Path:** Computes minimum-hop or lowest-latency routing between nodes.
- **Articulation Points (Cut Vertices):** Identifies single points of failure (e.g., switches or routers whose loss partitions the network).
- **Reachability Closure:** Transitive closure determining if an attacker on node $u$ can reach listening service $v$.