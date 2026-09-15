# Day 162: Real-Time Architecture Audit & Event/State Contract

## 1. Executive Summary & Core Separation Rule
The real-time synchronization layer connects the Phase 1–18 intelligence pipeline and Phase 19 3D rendering engine.

### Strict Conceptual Separation
- **Transport Connection States** (`CONNECTED`, `DISCONNECTED`, `RECONNECTING`): Pertain solely to the WebSocket link between client and server.
- **Data Freshness States** (`FRESH`, `STALE`, `UNKNOWN`): Determined by heartbeat delta age ($\Delta t > 2.0\text{s}$).
- **Backend Health States** (`HEALTHY`, `BACKEND_ERROR`, `UNAVAILABLE`): Describe upstream pipeline execution.
- **Digital Twin Domain States** (`NORMAL`, `MONITORED`, `SUSPICIOUS`, `AT_RISK`, `COMPROMISED`, `ISOLATED`): Represent actual network node security posture.
*Under no circumstances does `WebSocket = DISCONNECTED` equate to `Device = ISOLATED`.*

## 2. Event Envelope Structure
Every real-time event uses a standardized schema:
```json
{
  "eventId": "EVT-REALTIME-7A2B9C",
  "eventType": "DEVICE_STATE_UPDATE",
  "timestamp": "2026-09-15T09:48:33.123456Z",
  "receivedTimestamp": "2026-09-15T09:48:33.124100Z",
  "processedTimestamp": "2026-09-15T09:48:33.125200Z",
  "sequenceNumber": 10001,
  "simulationId": "SIM-4F1A29",
  "source": "SIMULATION_ENGINE",
  "deviceId": "WEB-01",
  "version": "1.0",
  "payload": { ... },
  "metadata": { ... }
}
3. Snapshot vs. Incremental Updates
Full Twin Snapshot (TwinStateSnapshot): Transmitted on initial WebSocket handshake and upon reconnection to establish baseline state across devices, links, traffic rates, threats, risks, and simulation stages.

Incremental Delta (RealtimeEventEnvelope): Emitted upon state mutations (e.g. CPU spikes, new alert, risk recalculation, quarantine). Minimizes network overhead and avoids re-rendering the full scene graph.