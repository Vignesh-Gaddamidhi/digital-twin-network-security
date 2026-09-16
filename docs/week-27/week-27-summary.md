# Week 27 Summary: Backend Persistence & Enterprise Data Layer

## 1. Architectural Transformation
Week 27 successfully transitions the Digital Twin & SOC Platform from transient in-memory models into a persistent, production-grade PostgreSQL backend hosted on Neon Cloud over secure SSL connections using SQLAlchemy 2.0 (asyncpg).

Simulation / Threat Event
│
▼
FastAPI Controller (:8000)
│
▼
Digital Twin State Engine (Authoritative In-Memory Runtime Graph)
│
▼
Service Layer & Unified DAL Repositories (SQLAlchemy 2.0 Asyncpg)
│                                       │
▼ (Async Persistent Record)             ▼ (Real-time Broadcast)
PostgreSQL (Neon Cloud Cluster)       WebSocket Gateway (:8000)
│
▼
Next.js SOC Console (:3000)


## 2. Master Domain Relational Coverage
| Domain | Entities Implemented |
|---|---|
| **Identity & RBAC** | `users`, `roles`, `permissions`, `role_permissions` |
| **Network Twin** | `devices`, `interfaces`, `services`, `ports`, `device_routes`, `connections`, `topology_edges` |
| **Telemetry & Flows** | `telemetry`, `traffic_flows` |
| **Security Detections** | `security_events`, `ids_events`, `alerts`, `incidents` |
| **ML & XAI** | `predictions`, `temporal_predictions`, `xai_explanations` |
| **Risk & Graph** | `risk_assessments`, `attack_paths` |
| **Simulation & CVE** | `simulations`, `simulation_runs`, `simulation_events`, `vulnerabilities` |
| **Governance & ML** | `audit_logs`, `datasets`, `ml_experiments`, `ml_models` |

## 3. Core Architectural Invariants Preserved
1. **Source-of-Truth Separation**: Digital Twin maintains the live authoritative in-memory graph; PostgreSQL is the durable historical source-of-record.
2. **Universal Identity Invariant**: Identity key alignment across all 9 subsystems:
   `Device ID` = `Twin Node` = `2D View` = `3D Mesh` = `Alert Subject` = `Prediction Target` = `Risk Subject`.
3. **Hard Safety Boundary**: Real physical network modifications are permanently blocked at the database DAL level (`ExecutionMode.REAL` raises `PermissionError` and creates an audit rejection record).