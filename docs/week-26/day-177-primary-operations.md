# Day 177: Security Operations Dashboard, Network Twin & Threat Detection

## 1. Unified Operational Pipeline
Day 177 turns the initial scaffolds into operational command surfaces connected to FastAPI (`:8000`) and the WebSocket gateway:

FastAPI Gateway (:8000)
│ (REST & WebSocket)
▼
Global SocContext Store
├── Part A: SOC Dashboard (Dynamic KPIs, Severity Breakdown, Risk Gauge, Live Feed)
├── Part B: Network Twin (Interactive Subnets, 2D SVG Topology, 3D Canvas Switcher, Drawer)
└── Part C: Threat Detection (Multi-Source DPI: Suricata, Zeek, Simulation, ML Detector)


## 2. Dynamic Metric Binding
- **KPI Ribbons**: Bound to `realtime_store_engine` asset registry, active alert triage queues, and composite network risk.
- **Threat Severity**: Dynamically aggregated across `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` tiers.
- **Multi-Source Detection**: Ingests normalized Suricata rules, Zeek flow tuples, and ML XGBoost/Random Forest detections.

## 3. Investigation Handoff Workflow
Operators can pivot directly from a live threat packet into an end-to-end incident investigation:
`Detection Frame` ➔ `Alert Record` ➔ `ML Prediction` ➔ `SHAP Waterfall` ➔ `Blast Radius Graph` ➔ `Incident Ticket`.