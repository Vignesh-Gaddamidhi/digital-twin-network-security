# Day 173: Digital Twin State Transition & Real-Time WebSocket Integration

## 1. The Response-to-Twin Architecture Path
Under no circumstances does the response engine push updates directly to UI viewports. State mutations flow through the single source of truth:

              Response Recommendation Engine
                             │
                             ▼
                 Response Action Executor
                             │
                             ▼
               [Digital Twin State Mutator]
         ├── Reads Current State (previousState)
         ├── Applies Simulated Delta (newState)
         ├── Appends Immutable Transition to State History
         ├── Updates Incident Links, Ports & Services
         └── Re-evaluates Attack Path Reachability (BLOCKED)
                             │
                             ▼
                 [Realtime Event Manager]
                 (Emits RESPONSE_UPDATE)
                             │
                             ▼
                [FastAPI WebSocket Stream]
                             │
                             ▼
               [Universal RealtimeStore]
                 ┌───────────┴───────────┐
                 ▼                       ▼
        2D Topology Canvas       3D WebGL Canvas

## 2. Attack Path Reachability Severing
When a critical node (such as `WEB-01`) is isolated via `ISOLATE_DEVICE`:
- `attack_path_graph.nodes["WEB-01"].securityState = "ISOLATED"`
- All traversed edges (`CLIENT-01` -> `WEB-01`, `WEB-01` -> `DB-01`) are marked `BLOCKED`.
- The attack path status transitions from `REACHABLE` to `BLOCKED`.
- The 3D spline dims and displays containment wireframe indicators.

## 3. Dedicated `RESPONSE_UPDATE` Real-Time Contract
```json
{
  "eventId": "RTE-XXXXXXXX",
  "eventType": "RESPONSE_UPDATE",
  "timestamp": "2026-09-16T09:00:00.000000+00:00",
  "responseId": "RESP-20260916-000001",
  "action": "ISOLATE_DEVICE",
  "affectedDevice": "WEB-01",
  "previousState": "NORMAL",
  "newState": "ISOLATED",
  "result": { "status": "SUCCESS", "twinUpdated": true },
  "mode": "SIMULATION"
}