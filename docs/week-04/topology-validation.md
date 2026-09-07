# Day 24: Topology Validation & Query Engine

## 1. Core Verification Queries
A validated network topology model must support automated answering of:
1. **Connectivity Check:** `is_connected(D001, D002)` returns boolean connectivity state.
2. **Transit Path Tracing:** `find_path(D001, D002)` returns ordered list of intermediate hops `[D001, D005, D002]`.
3. **Reachability Surface:** `get_reachable_devices(D001)` returns all reachable active peers.
4. **Structural Dependency Analysis:** `get_dependent_nodes(D005)` returns all hosts that depend on the core switch for network connectivity.