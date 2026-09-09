# Day 74: SCN-DOS-001 (Synthetic Traffic Saturation Pattern)

## 1. Objective
Model high-volume volumetric saturation targeting `WEB-01` by reusing the Phase 7 traffic spike engine without external network floods or socket exhaustion.

## 2. Scenario Contract
- **Scenario ID:** `SCN-DOS-001`
- **Category:** `DOS`
- **Severity:** `HIGH`
- **Target:** `WEB-01`
- **Preconditions:**
  1. `WEB-01` exists in Device Registry.
  2. Web service (HTTP/HTTPS) exists on port 80 or 443.
  3. Network path between `CLIENT-01` and `WEB-01` exists.
- **Expected Indicators:**
  - `TRAFFIC_VOLUME_SPIKE`: Packet throughput surge exceeds threshold (> 50 pkts/sec).
  - `HIGH_PACKET_RATE`: Aggregate frame emission rate exceeds threshold (> 50 pkts/sec).
  - `HIGH_CONNECTION_RATE`: Simultaneous connection creation surges (> 5.0 conns/sec).
  - `HIGH_NETWORK_UTILISATION`: Ingress wire utilisation exceeds threshold (> 80.0%).
- **Twin State Degradation:**
  - Line Utilisation: 20.0% -> 95.0%
  - CPU Load: 25.0% -> 85.0%
  - Active Sockets: 5 -> 40
- **Recovery:**
  - Reset host metrics to steady baseline (CPU 25%, Util 20%).
  - Purge socket allocations and verify state.