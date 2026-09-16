# Day 186: Telemetry, Traffic & Security Event Persistence

## 1. High-Throughput Relational Architecture
Day 186 defines the streaming telemetry and security event models in PostgreSQL:

┌─────────────────┐        ┌──────────────────┐
│    telemetry    │        │  traffic_flows   │
├─────────────────┤        ├──────────────────┤
│ id (PK)         │        │ id (PK)          │
│ device_id (FK)  │        │ source_ip        │
│ timestamp       │        │ destination_ip   │
│ cpu_usage       │        │ source_port      │
│ memory_usage    │        │ destination_port │
│ packet_rate     │        │ protocol         │
│ byte_rate       │        │ packet_count     │
│ risk_score      │        │ byte_count       │
└─────────────────┘        └──────────────────┘

┌─────────────────┐ (1:N)  ┌──────────────────┐
│ security_events │◄───────│    ids_events    │
├─────────────────┤        ├──────────────────┤
│ event_id (PK)   │        │ id (PK)          │
│ source/dest     │        │ signature_id     │
│ device_id (FK)  │        │ signature        │
│ event_type      │        │ sensor           │
│ severity        │        │ sec_event_id(FK) │
└─────────────────┘        └──────────────────┘


## 2. Event Model Distinction
- **Telemetry**: Continuous host metrics (`cpu`, `memory`, `pps`, `bps`).
- **Traffic Flows**: Network flow summaries (NetFlow/IPFIX tuples: source/destination IPs, ports, bytes, durations).
- **IDS Events**: Raw sensor alert events from detection engines (Suricata rule signatures, Zeek notices).
- **Security Events**: Normalized SIEM event objects correlated from multiple detection sources.
- **Alerts**: Priority-triaged records surfaced on the SOC console.

## 3. Query Performance & Indexing
To prevent sequential table scans as telemetry scales:
- `telemetry` is indexed by `(device_id, timestamp DESC)` and `timestamp DESC`.
- `traffic_flows` is indexed by `(source_ip, destination_ip)`, `protocol`, and `timestamp DESC`.
- `security_events` is indexed by `(deviceId)`, `eventType`, `severity`, and `timestamp DESC`.
- `ids_events` is indexed by `signatureId`, `sensor`, and `timestamp DESC`.