# Day 50: Simulation Engine Architecture & Discrete Clock

## 1. Core Principles
1. **Discrete Virtual Clock:** Simulators cannot rely on `time.time()` wall-clock timestamps because asynchronous system pauses, network latency, and CPU throttle alter test runs. The `SimulationClock` maintains an internal tick counter $T_{\text{sim}} \ge 0$, advancing by fixed quantum steps ($\Delta t$).
2. **Deterministic Seeding:** Given identical `seed` and `scenarioId`, the pseudo-random generator produces identical packet sizes, inter-arrival intervals, and port selections across runs.
3. **Simulation Lifecycle States:**
   - `CREATED`: Scenario parsed, validated, and loaded.
   - `RUNNING`: Virtual clock ticking, events actively generated and queued.
   - `PAUSED`: Clock frozen at current $T_{\text{sim}}$, events buffered.
   - `COMPLETED`: Virtual clock reached target scenario `duration`.
   - `STOPPED`: Manually terminated prior to duration expiry.
   - `FAILED`: Aborted due to unhandled execution exception.

## 2. Event Payload Contract
```json
{
  "eventId": "sim-event-001",
  "scenarioId": "normal-office-001",
  "simTimeSeconds": 2.0,
  "timestamp": "2026-09-08T14:30:02.000000Z",
  "sourceDevice": "client-01",
  "destinationDevice": "web-01",
  "protocol": "TCP",
  "sourcePort": 52000,
  "destinationPort": 443,
  "eventType": "CONNECTION",
  "payloadSize": 1024,
  "status": "SUCCESS"
}