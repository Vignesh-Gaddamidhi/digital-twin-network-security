# Day 185: Digital Twin Database Persistence

## 1. Structural Decomposition Architecture
Day 185 replaces opaque JSON blob storage with normalized relational database models:

                      ┌──────────────┐
                      │   devices    │
                      ├──────────────┤
                      │ id (PK)      │
                      │ hostname     │
                      │ network_zone │
                      │ primary_ip   │
                      │ ip_addresses │
                      │ mac_addresses│
                      │ os, role     │
                      │ sec_state    │
                      │ risk_score   │
                      └──────┬───────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│  interfaces  │        │   services   │        │    ports     │
├──────────────┤        ├──────────────┤        ├──────────────┤
│ device_id(FK)│        │ device_id(FK)│        │ device_id(FK)│
│ name, ip     │        │ name, port   │        │ port, proto  │
│ subnet, speed│        │ proto, status│        │ state (Enum) │
└──────────────┘        └──────────────┘        └──────────────┘

                      ┌──────────────┐
                      │   devices    │ (Source & Target)
                      └──────┬───────┘
                             │
     ┌───────────────────────┴───────────────────────┐
     ▼                                               ▼
┌──────────────┐                                ┌──────────────┐
│ connections  │ (Flow Metrics)                 │topology_edges│ (Graph G = (V,E))
├──────────────┤                                ├──────────────┤
│ id (PK)      │                                │ id (PK)      │
│ src_dev (FK) │                                │ src_dev (FK) │
│ dst_dev (FK) │                                │ dst_dev (FK) │
│ proto, ports │                                │ edge_type    │
│ packet_count │                                │ weight       │
└──────────────┘                                └──────────────┘


## 2. Universal Identity Invariant
To prevent state divergence, the identical string asset key (e.g. `WEB-01`) is maintained as the primary key across:
`Database Device ID` = `Twin Graph Node ID` = `2D Topology ID` = `3D Mesh ID` = `Alert Subject` = `Prediction Target` = `Risk Subject`.