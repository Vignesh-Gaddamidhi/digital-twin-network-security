# Day 72: SCN-PORTSCAN-001 (Synthetic Port Discovery Pattern)

## 1. Objective
Simulate horizontal port reconnaissance directed from `CLIENT-01` toward `SERVER-01` across ports `21, 22, 25, 53, 80, 443, 8080` without deploying weaponized socket scanners.

## 2. Scenario Contract
- **Scenario ID:** `SCN-PORTSCAN-001`
- **Category:** `PORT_SCAN`
- **Severity:** `MEDIUM`
- **Target:** `SERVER-01`
- **Preconditions:**
  1. `CLIENT-01` exists in registry.
  2. `SERVER-01` exists in registry.
  3. Topological network path exists between `CLIENT-01` and `SERVER-01`.
- **Expected Indicators:**
  - `UNUSUAL_PORT_ACTIVITY`: Unique ports accessed exceeds threshold (> 5.0).
  - `HIGH_UNIQUE_PORT_COUNT`: Distinct targeted destination ports (> 5.0).
  - `HIGH_FAILED_CONNECTION_RATE`: Failed handshakes resulting in `RST` exceed threshold (> 3.0).
- **Recovery:**
  - Close simulated sockets, reset socket tables to 0, verify healed status.