# Day 77: SCN-LATERAL-001 (Synthetic Lateral Connection Pattern)

## 1. Objective
Model multi-hop east-west pivot traversal across `CLIENT-01 -> SERVER-01 -> SERVER-02 -> DB-01` without performing real privilege escalation, remote code execution, or credential dumping.

## 2. Scenario Contract
- **Scenario ID:** `SCN-LATERAL-001`
- **Category:** `LATERAL_MOVEMENT`
- **Severity:** `HIGH`
- **Source:** `CLIENT-01`
- **Target:** `SERVER-01` (entry jump host) propagating to `DB-01`
- **Preconditions:**
  1. `CLIENT-01`, `SERVER-01`, `SERVER-02`, and `DB-01` exist in Device Registry.
  2. Network topology graph links all four devices through switches/routers.
  3. Target services exist on respective hops (Port 22 on SERVER-01, Port 445 on SERVER-02, Port 5432 on DB-01).
- **Expected Indicators:**
  - `UNUSUAL_DEVICE_SEQUENCE`: Chained multi-hop traversal observed.
  - `NEW_INTERNAL_CONNECTION`: Novel east-west internal connection created.
  - `MULTI_HOST_CONNECTION_PATTERN`: Unique traversed host count >= 3.
  - `UNUSUAL_DESTINATION`: Indirect reachability from client tier into database tier.
  - `INCREASED_INTERNAL_CONNECTIONS`: Count of internal connection handshakes surges (> 2).
- **Recovery:**
  - Teardown all transient east-west socket connections.
  - Reset graph connection state to baseline.
  - Verify zero lingering pivot sessions on intermediate jump boxes.