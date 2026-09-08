# Day 58: Abnormal Traffic Simulation Framework

## 1. Separation of Observation and Interpretation
An authentic digital twin maintains a strict separation:
- **Simulation Layer (Observation):** Emits measurable network signals—packet counts, frame sizes, port hits, and arrival timings.
- **Detection Layer (Interpretation):** Ingests baseline statistics from Week 8, evaluates statistical deviations (Z-score, IQR, entropy), and declares security alerts.

## 2. Core Anomaly Types
1. `TRAFFIC_SPIKE`: Sudden volumetric rate escalation ($\times 5$ to $\times 100$) saturating link throughput.
2. `CONNECTION_ANOMALY`: Rapid surge in concurrent or short-lived TCP handshakes.
3. `PORT_ANOMALY`: Access attempts spanning unallocated, non-standard, or filtered ports.
4. `PROTOCOL_ANOMALY`: Deviation in normal protocol distribution ratios (e.g., DNS volume exceeds HTTPS by $10\times$).
5. `REPEATED_CONNECTION`: Looped connection establishment and teardown to a single target endpoint.

## 3. Abnormal Event Payload
```json
{
  "eventId": "abnormal-001",
  "simulationId": "sim-001",
  "deviceId": "client-01",
  "targetDevice": "web-01",
  "anomalyType": "TRAFFIC_SPIKE",
  "severity": "MEDIUM",
  "intensity": 5.0,
  "timestamp": "2026-09-08T18:00:00.000000Z",
  "details": {
    "baselineRateBps": 9174.0,
    "observedRateBps": 45870.0,
    "multiplier": 5.0
  }
}