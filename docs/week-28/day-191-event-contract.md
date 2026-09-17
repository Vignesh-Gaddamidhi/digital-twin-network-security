# Day 191: Canonical Event Contract & Redis Event Bus

## 1. Standardized Envelope Structure
Every real-time event across the Digital Twin platform conforms to the `CanonicalEvent` envelope:

| Field | Type | Description |
|---|---|---|
| `eventId` | String (UUID) | Unique monotonic identifier for event deduplication. |
| `eventType` | Enum | One of 19 platform categories (Telemetry, Threat, Alert, Response). |
| `timestamp` | ISO-8601 UTC | Microsecond event creation time. |
| `source` | String | Subsystem emitting the event (`TWIN_CORE`, `SURICATA`, `ML_ENGINE`). |
| `environment` | String | Execution context (`PRODUCTION`, `SIMULATION_SANDBOX`). |
| `correlationId` | String (UUID) | Root transaction identifier linking initial exploit to eventual containment. |
| `causationId` | String (UUID) | Immediate parent event triggering this reaction. |
| `deviceId` | String | Target network asset (`WEB-01`, `DB-01`). |
| `severity` | Enum | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `schemaVersion`| String | Contract version (`1.0`) preventing consumer drift. |
| `sequence` | Integer | Counter for monotonic in-order packet reconstruction. |
| `payload` | Dict | Domain-specific entity details. |

## 2. Causal Correlation Lineage
[Simulation Pulse] (correlationId: X, causationId: None)
↓
[Traffic NetFlow] (correlationId: X, causationId: Pulse_ID)
↓
[Suricata Signature] (correlationId: X, causationId: Flow_ID)
↓
[ML Prediction] (correlationId: X, causationId: Sig_ID)
↓
[Security Alert] (correlationId: X, causationId: Pred_ID)
↓
[Simulated Response Action] (correlationId: X, causationId: Alert_ID)


## 3. Idempotent Deduplication Guarantee
Consumers query atomic Redis keys (`cybertwin:dedup:{eventId}`, TTL: 300s) prior to dispatching state mutations, guaranteeing that network retransmissions or WebSocket reconnects do not trigger duplicate state alterations.