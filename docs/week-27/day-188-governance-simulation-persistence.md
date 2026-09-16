# Day 188: Simulation, Vulnerability, Audit & ML Governance Persistence

## 1. Governance & Simulation Relational Schema
Day 188 completes the remaining database domains:

┌──────────────────┐ (1:N) ┌──────────────────┐ (1:N) ┌───────────────────┐
│   simulations    │──────►│ simulation_runs  │──────►│ simulation_events │
├──────────────────┤       ├──────────────────┤       ├───────────────────┤
│ simulation_id    │       │ run_id (PK)      │       │ event_id (PK)     │
│ name             │       │ sim_id (FK)      │       │ run_id (FK)       │
│ scenario         │       │ status, duration │       │ device_id, proto  │
│ default_config   │       │ seed, speed      │       │ payload_metadata  │
└──────────────────┘       └──────────────────┘       └───────────────────┘

┌──────────────────┐       ┌──────────────────┐
│ vulnerabilities  │       │    audit_logs    │
├──────────────────┤       ├──────────────────┤
│ vulnerability_id │       │ audit_id (PK)    │
│ device_id (FK)   │       │ operator_id      │
│ identifier (CVE) │       │ action (6 types) │
│ severity, cvss   │       │ mode (SIM vs REAL│
│ status (5 states)│       │ result (Blocked) │
└──────────────────┘       └──────────────────┘

┌──────────────────┐
│     datasets     │
├──────────────────┤
│ dataset_id (PK)  │
│ name, version    │
│ row/feature_cnt  │
└─────────┬────────┘
│ (1:N)
┌─────┴──────────────────┐
▼                        ▼
┌──────────────────┐   ┌──────────────────┐
│  ml_experiments  │   │    ml_models     │
├──────────────────┤   ├──────────────────┤
│ experiment_id    │   │ model_id (PK)    │
│ dataset_id (FK)  │   │ dataset_id (FK)  │
│ metrics (F1/AUC) │   │ metrics, latency │
│ conf_matrix      │   │ artifact_ref(S3) │
└──────────────────┘   └──────────────────┘


## 2. Hard Safety Boundary Invariant
The `audit_logs` table records all automated and human interventions. In accordance with the Week 25 Safety Boundary:
- Any record submitted with `mode = "REAL"` triggers a database audit entry flagged as `REJECTED_SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED` and immediately raises a `PermissionError`.
- Only `SIMULATION` mode actions are allowed.