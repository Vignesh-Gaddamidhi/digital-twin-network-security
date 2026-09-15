# Day 164: Simulation → Event → FastAPI → Digital Twin Real-Time Pipeline

## 1. Simulation Lifecycle State Transitions
The simulation control pipeline governs deterministic state progression:
- `CREATED`: Baseline initialized with deterministic PRNG seed.
- `RUNNING`: Emits discrete ticks, advances simulated time, and drives packet flows.
- `PAUSED`: Halts tick generation; freezes traffic particle movement.
- `RESUMED`: Resumes execution ticks from the paused timestamp without drift.
- `STOPPED`: Terminates active scenario runs; marks final tick summary.
- `RESET`: Restores canonical node security baselines without clearing device inventories.

## 2. Event Normalization & Twin Mutation Rule
Under no circumstances does simulation telemetry flow directly to the frontend:
Simulation Event ──> Normalize ──> Mutate Digital Twin ──> WebSocket Envelope ──> Frontend

Every packet surge or port anomaly must first mutate `attack_path_graph` or device telemetry before generating a `RealtimeEventEnvelope`.

## 3. Supported Event Taxonomy
- **Normal Telemetry**: `TCP`, `UDP`, `ICMP`, `HTTP`, `HTTPS`, `DNS`, `SSH`
- **Anomalous Patterns**: `TRAFFIC_SPIKE`, `CONNECTION_ANOMALY`, `PORT_ANOMALY`, `PROTOCOL_ANOMALY`, `REPEATED_CONNECTION`
- **Multi-Stage Attack Scenarios**: `LATERAL_MOVEMENT_LIKE`, `EXFILTRATION_LIKE`, `DOS_SATURATION_LIKE`