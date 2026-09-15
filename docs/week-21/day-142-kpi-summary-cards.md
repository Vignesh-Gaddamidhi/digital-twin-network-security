# Day 142: KPI Summary Cards (Devices, Threats, Risk & Attacks)

## 1. Metric Semantic Decoupling
To avoid presenting misleading figures to SOC operators:
- **Devices:** `totalDevices = activeDevices + atRiskDevices + isolatedDevices`.
- **Threats:** Sourced directly from normalized alerts, partitioned strictly by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Risk:** Reflects network-wide aggregate risk from the Phase 16 Engine (`MAX` or `TOP_N`), including trajectory trend (`↑`, `↓`, `→`).
- **Attacks:** Decoupled into `detected` (active IDS events), `predicted` (ML time-series early warnings), and `simulated` (controlled lab scenarios).

## 2. Staleness and Refresh Semantics
- Each KPI evaluation captures `lastRefreshedAt`.
- If $\Delta t > 60\text{ seconds}$ without an incoming telemetry pulse, the dashboard flags the metric state as `STALE`.