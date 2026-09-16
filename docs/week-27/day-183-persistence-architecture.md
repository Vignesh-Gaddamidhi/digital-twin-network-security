# Day 183: PostgreSQL Architecture & Persistence Foundation

## 1. Database Architecture
Week 27 establishes PostgreSQL as the persistent source-of-record, deployed via Neon Serverless PostgreSQL with pooling over port 5432 and SSL:

[Simulations / Telemetry]
│
▼
[FastAPI Backend :8000]
│                 │
(Async Sync)       (Live Feed)
▼                 ▼
[Prisma DAL]      [Digital Twin In-Memory Graph]
│                 │
▼                 ▼
[Neon PostgreSQL] [WebSocket Realtime Gateway]
│
▼
[Next.js SOC Console :3000]


## 2. Source-of-Truth Invariants
1. **Live State**: The in-memory Digital Twin graph engine remains the authority for live operational state, attack paths, and simulations.
2. **Historical Ledger**: PostgreSQL is the immutable source for audit logs, incident histories, user configurations, and model metadata.
3. **Write-Through Caching**: State mutations are applied to the in-memory Digital Twin first, then asynchronously persisted via the repository layer.

## 3. Database Domains
- **Identity**: `users`, `roles`
- **Network Twin**: `devices`, `device_interfaces`, `device_services`, `device_ports`, `device_routes`, `network_connections`
- **Telemetry**: `telemetry_records`, `traffic_flows`
- **Security**: `security_events`, `alerts`, `incidents`
- **AI & XAI**: `threat_predictions`, `xai_explanations`
- **Risk**: `risk_assessments`, `attack_paths`
- **Simulation**: `simulation_runs`, `vulnerabilities`
- **Governance**: `audit_logs`