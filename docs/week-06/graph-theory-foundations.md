# Day 36: Graph Theory Foundations for Network Digital Twin

## 1. Mathematical Formalism
The digital twin network is formalized as a directed attributed multigraph:
$$G = (V, E, \mu, \nu)$$

Where:
- $V$: Set of vertices representing physical/virtual devices.
- $E$: Directed multiset of ordered pairs $(u, v)$ representing network relations.
- $\mu: V \to \text{Attributes}$: Vertex mapping function (type, label, zone, state).
- $\nu: E \to \text{Attributes}$: Edge mapping function (protocol, port, status, latency).

## 2. Graph Engine Operations
| Operation | Complexity | Description |
|---|---|---|
| `addNode(node)` | $O(1)$ | Registers node and metadata attributes |
| `removeNode(id)` | $O(\deg(v))$ | Purges node and cascades removal of all incident edges |
| `addEdge(edge)` | $O(1)$ | Connects source to target with connection metrics |
| `removeEdge(id)` | $O(1)$ | Drops specific connection edge |
| `getNeighbors(id)` | $O(\deg(v))$ | Returns adjacent nodes (predecessors, successors, or undirected) |
| `getNodes(filter)` | $O(|V|)$ | Queries active nodes with optional zone/type filters |
| `getEdges(filter)` | $O(|E|)$ | Queries active edges with optional status/protocol filters |