# Day 164: Simulation → Event → FastAPI → Digital Twin Real-Time Pipeline

## 1. Unified Event Flow
The simulation event pipeline bridges synthetic scenario execution and real-time frontend visualization:

[UI Trigger: START]
│
▼
[Simulation Engine Tick]
│
▼
[Normalize Simulation Event]
│
▼
[Update Canonical Twin (attack_path_graph)] ──> [Security/Risk Update]
│
▼
[Package RealtimeEventEnvelope (Monotonic Seq)]
│
▼
[WebSocket Broadcast (/api/v1/twin/realtime/ws/live)]
│
▼
[Next.js Client: Ingest Frame -> Mutate 2D & 3D WebGL Views]


## 2. Invariant: Never Bypass the Twin
The frontend never receives synthetic events directly from the simulation runner. All simulation output passes through canonical Twin nodes and edges first. The WebGL canvas and 2D topology render only what exists in the canonical Digital Twin.

## 3. Supported Live Scenario Events
1. **Normal Telemetry**: Baseline TCP, UDP, ICMP, HTTP, HTTPS, DNS, SSH traffic across active links.
2. **Volumetric Spikes**: `TRAFFIC_SPIKE` driving packet rates from 120 pkt/s to 1,500+ pkt/s.
3. **Anomalous Behavioral Probes**:
   - `PORT_ANOMALY`: Rapid port discovery triggering ML classifier alerts.
   - `CONNECTION_ANOMALY`: Abnormal outbound connection rates.
   - `PROTOCOL_ANOMALY`: Non-standard payloads on standard ports.
   - `REPEATED_CONNECTION`: Beaconing behavior matching C2 heuristics.
4. **Phase 8 Lateral Scenarios**: `LATERAL_MOVEMENT_LIKE`, `EXFILTRATION_LIKE`.