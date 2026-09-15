# Day 165: Live Device, Telemetry, Traffic & Connection Updates

## 1. High-Frequency Decoupling Architecture
High event ingestion rates must not overload browser rendering engines:
Simulation / Telemetry Engine (1000 events/sec)
│
▼
LiveTelemetryEngine Buffer
│
┌─────────┴─────────┐
▼                   ▼
Complete Ingest       Throttled Window Aggregation (100ms / 250ms)
(Security Invariant)        │
▼
WebSocket Broadcast Envelope
│
┌────────────┴────────────┐
▼                         ▼
2D Topology Canvas        3D Three.js Canvas
- Live Gauge Cards        - Shader Emissive Pulses
- Selected Side-Drawer    - Particle Speed / Glow


## 2. Dynamic Connection Lifecycle Taxonomy
Connections progress through explicit lifecycle states:
- `NEW`: Socket handshake initiated.
- `CONNECTING`: Syn-Ack exchange in flight.
- `ESTABLISHED`: Actively transmitting payload bytes.
- `CLOSING`: Fin-Ack teardown requested.
- `CLOSED`: Connection terminated normally.
- `FAILED`: Connection reset (`RST`) or dropped due to firewall rule.

## 3. Selected Device Live Streaming Invariant
When a user selects a device (e.g. `WEB-01`), any incoming telemetry event (`CPU_UPDATE`, `MEMORY_UPDATE`, `DEVICE_STATE_UPDATE`) immediately mutates the inspection model without triggering full-page DOM updates or camera resets.