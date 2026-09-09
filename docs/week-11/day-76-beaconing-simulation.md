# Day 76: SCN-BEACON-001 (Periodic Communication Pattern)

## 1. Objective
Model an automated command-and-control (C2) heartbeat beacon from `CLIENT-01` to `SERVER-01` over HTTPS (port 443) using deterministic periodicity and bounded pseudo-random jitter without executable malware.

## 2. Scenario Contract
- **Scenario ID:** `SCN-BEACON-001`
- **Category:** `BEACONING`
- **Severity:** `HIGH`
- **Source:** `CLIENT-01`
- **Target:** `SERVER-01`
- **Preconditions:**
  1. `CLIENT-01` exists in registry.
  2. `SERVER-01` exists in registry.
  3. Port 443 is OPEN on `SERVER-01`.
  4. Topological path between `CLIENT-01` and `SERVER-01` exists.
- **Expected Indicators:**
  - `PERIODIC_TRAFFIC`: Inter-packet timing variance is compressed (< 0.05s²).
  - `REPEATED_DESTINATION`: Outbound attempts to identical destination socket exceed threshold (> 8 attempts).
  - `REGULAR_TIME_INTERVAL`: Ratio of regular interval occurrences approaches 1.0 (> 0.85).
  - `UNUSUAL_CONNECTION_FREQUENCY`: Persistent background connection frequency detected (> 0.8 conns/sec).
- **Recovery:**
  - Terminate periodic traffic loop, purge active socket sessions, restore baseline telemetry.