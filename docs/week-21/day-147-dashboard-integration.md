# Day 147: Master Security Simulation Dashboard Integration & Testing

## 1. Unified Dashboard Ingestion Architecture
To ensure responsive real-time rendering on standard desktop environments and eliminate N+1 API cascades, the frontend relies on:
- **`GET /api/v1/twin/dashboard/summary`**: Serves the unified initial render bundle containing KPIs, topology graph projection, traffic velocity, active threat events, predictions, and prioritized attack paths.
- **Specialized Topic Routes**: Queried on demand during user drill-downs:
  - `GET /api/v1/twin/topology/live`
  - `GET /api/v1/twin/traffic/live`
  - `GET /api/v1/twin/threats/timeline`
  - `GET /api/v1/twin/predictions/xai`
  - `POST /api/v1/twin/attack-path/scoring/rank`

## 2. Cross-Subsystem State Consistency Invariant
All components derive telemetry from the authoritative `twin_engine` state:
$$\text{DeviceState}(d) \equiv \text{TopologyNode}(d) \equiv \text{RiskEngine}(d) \equiv \text{AttackPath}(d)$$
When a device risk escalates, its node border, KPI risk pill, threat timeline entry, and attack-path vulnerability weighting update consistently without contradictory states.

## 3. Simulation Lifecycle Control
The simulation control service governs:
- Operational States: `RUNNING`, `PAUSED`, `STOPPED`, `RESET`.
- Scenarios: `NORMAL`, `TRAFFIC_SPIKE`, `LATERAL_MOVEMENT_LIKE`, `EXFILTRATION_LIKE`.
- Virtual Speed: $1\times, 2\times, 5\times$.