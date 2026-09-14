# Day 142: Executive KPI Cards & Security Overview Grid

## 1. Primary KPI Matrix
| Card | Primary Metric | Sub-Metrics | Route Drill-Down |
|---|---|---|---|
| **DEVICES** | Total Devices (e.g., `12`) | Normal, Monitored, Suspicious, At Risk, Compromised, Isolated | `devices` |
| **THREATS** | Active Threats (e.g., `4`) | Critical, High, Medium, Low severity distribution | `threats` |
| **RISK** | Overall Network Risk (e.g., `HIGH 69.6`) | Max Node Risk, Risk Trend (`INCREASING`), Highest Node | `risk` |
| **ATTACKS** | Active Scenarios (e.g., `3`) | Simulation status, active scenario names (`LATERAL_MOVEMENT_LIKE`) | `attack-paths` / `simulation` |

## 2. Secondary Contextual Overviews
- **Critical Assets at Risk:** Explicit display of crown jewels (`DB-01`, `WEB-01`) currently exposed.
- **Open Security Alerts:** Real-time event counter from Phase 16 transition ledger.
- **Active ML Predictions:** Inference counter from Phase 13/14 prediction engines.