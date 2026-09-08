# Phase 5: Reachability Engine & Multi-Hop Path Analysis
Evaluates security-constrained reachability:
$$\text{Reachable}(A \to B) \iff \text{Path}(A \sim B) \land \text{Online}(A, B, \text{Hops}) \land \text{Active}(\text{Edges}) \land \text{FirewallPermit}(A \to B)$$
- Evaluates unweighted BFS minimum-hop paths.
- Enforces port-listening status on destination hosts.
- Inspects firewall policy across inter-zone boundaries.