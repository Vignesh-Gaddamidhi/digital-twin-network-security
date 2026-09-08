# Day 63: Repeated Connection Attempts Simulation

## 1. Concept
Normal client traffic initiates a session, transacts, and pauses or maintains keep-alives. A repeated connection anomaly models tight reconnect loops:
- Automated rapid connection attempts (e.g., 100 attempts in 10s).
- High failure ratio (e.g., 97 failed resets/drops, 3 successes).
- Structured telemetry records `attemptCount`, `successfulCount`, `failedCount`, and `windowSeconds`.

## 2. Event Contract
```json
{
  "eventId": "rep-conn-001",
  "anomalyType": "REPEATED_CONNECTION",
  "sourceDevice": "client-01",
  "destinationDevice": "server-01",
  "destinationPort": 22,
  "attemptCount": 100,
  "successfulCount": 3,
  "failedCount": 97,
  "windowSeconds": 10
}