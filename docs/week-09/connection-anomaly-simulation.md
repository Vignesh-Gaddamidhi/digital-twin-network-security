# Day 60: Connection Anomaly Simulation

## 1. Physical vs. Categorical Modeling
The simulator records measurable socket behavior:
- **Normal:** Moderate connection rates (~5 active connections per host) with orderly closures (`CLOSED`).
- **Anomalous:** Connection bursts scaling up to 100+ attempts with incomplete lifecycles (`NEW` -> `FAILED` / `RST`).
- **Classification:** Categorized neutrally as `UNUSUAL_CONNECTION_BEHAVIOUR` so downstream machine learning or heuristic detectors can make their own classification.

## 2. Session Lifecycle Tracking
Tracks dynamic states:
- `NEW`: Socket SYN allocated.
- `ESTABLISHED`: Full 3-way handshake concluded.
- `CLOSED`: Graceful `FIN`/`ACK` teardown.
- `FAILED`: Socket timeout, handshake drop, or reset (`RST`).

## 3. Configuration Contract
```json
{
  "scenarioId": "conn-anom-001",
  "affectedDevice": "client-01",
  "targetDevice": "web-01",
  "targetPort": 443,
  "protocol": "TCP",
  "normalConnectionRate": 5,
  "abnormalConnectionRate": 100,
  "durationSeconds": 15,
  "lifecyclePattern": "HALF_OPEN_OR_FAILING"
}