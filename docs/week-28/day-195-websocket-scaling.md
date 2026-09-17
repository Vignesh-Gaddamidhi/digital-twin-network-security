# Day 195: WebSocket Distribution, Caching & Realtime SOC Integration

## 1. Multi-Instance Fan-Out Architecture
Day 195 implements horizontal WebSocket distribution:

[Producer / Engine]
│
▼
[Redis Pub/Sub Channel: cybertwin:channel:realtime]
│
┌────┴─────────────────────────────┐
▼                                  ▼
[FastAPI Instance A]          [FastAPI Instance B]
│                                  │
├── Local WS Clients (All)         ├── Local WS Clients (Filtered)
└── Topic Filter: DEVICE:WEB-01    └── Topic Filter: ALERTS


## 2. Granular Topic Subscriptions
Clients customize ingestion traffic by sending a `SUBSCRIBE` control frame:
```json
{
  "action": "SUBSCRIBE",
  "topics": ["DEVICE:WEB-01", "ALERTS"]
}
Non-matching events are discarded at the gateway level to minimize client browser frame-drop rates.

3. Ephemeral Invalidation & Reconnect Snapshot
TTL Hierarchy: Telemetry (10s), Dashboard KPI (15s), Risk (20s), Alerts/Incidents (30s), Topology (300s).

Snapshot Resync: Reconnecting clients (CONNECTED -> DISCONNECTED -> RECONNECTING -> CONNECTED) receive a SNAPSHOT_RESYNC payload containing the latest valid Redis cache snapshot, eliminating empty state flashes.