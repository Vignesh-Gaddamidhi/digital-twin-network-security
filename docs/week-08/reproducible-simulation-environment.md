# Day 51: Reproducible Simulation Environment

## 1. Mathematical Determinism
To achieve mathematical reproducibility across distributed runs:
1. **Isolated PRNG Instance:** The simulation uses an isolated instance of Python's Mersenne Twister (`random.Random(seed)`). It never calls global `random.seed()`, preventing cross-thread interference or external library side effects.
2. **Monotonic Sequence Indexing:** Every event carries a strictly incrementing `sequenceNumber` ($1, 2, 3, \dots, N$).
3. **Discrete Delta Stepping:** Event timestamps derive from $T_{\text{sim}} = k \cdot \Delta t$, independent of host OS scheduling or wall-clock jitter.

## 2. Simulation Execution Configuration Contract
```json
{
  "simulationId": "sim-001",
  "runId": "run-f1e2d3c4",
  "scenarioId": "scenario-office-01",
  "seed": 12345,
  "duration": 300,
  "tickInterval": 1000,
  "speed": 1.0,
  "startTime": "2026-09-08T14:30:00.000000Z",
  "endTime": "2026-09-08T14:35:00.000000Z"
}
##3. Persistent Event Streaming (JSONL)
Events are serialized as JSON Lines to data/simulation/simulation-events.jsonl:
{"sequenceNumber":1,"eventId":"sim-evt-0001","simulationId":"sim-001","runId":"run-f1e2d3c4","simTimeSeconds":1.0,"sourceDevice":"client-01","destinationDevice":"web-01","protocol":"TCP","sourcePort":52410,"destinationPort":443,"payloadSize":1420,"status":"SUCCESS"}