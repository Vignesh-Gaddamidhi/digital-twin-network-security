# Day 179: Predictions, Alerts, Incidents & Investigation View

## 1. The Investigation Workflow
Day 179 introduces the core SOC investigation lifecycle, bridging raw detection to autonomous response playbooks:

[Detection Event] ──> [Alert Triage] ──> [Correlated Incident]
│                     │
▼                     ▼
[Dual-Horizon Prediction] ──> [10-Stage Investigation Timeline]
│                     │
▼                     ▼
[SHAP XAI & Risk] ──> [Simulated Playbook Execution]


## 2. Canonical Incident Model
IncidentRecord
├── incidentId: INC-YYYYMMDD-XXXXXX
├── title: Descriptive incident scope
├── description: Root cause summary
├── severity: CRITICAL | HIGH | MEDIUM | LOW
├── status: OPEN | INVESTIGATING | CONTAINED | RESOLVED | CLOSED
├── createdAt / updatedAt: ISO 8601 UTC timestamps
├── affectedDevices: Set of targeted nodes
├── relatedAlerts: Correlated alert IDs
├── predictions: Attached forecast records
├── riskAssessments: Composite scores
├── attackPaths: Traversed vector IDs
├── responses: Dispatched playbook executions
├── assignedOperator: Current analyst
└── timeline: 10-Stage chronological event progression


## 3. Dual-Horizon Distinction
Temporal forecasting strictly separates immediate threat probability ($P_{\text{current}}$) from predictive early warning probability ($P_{\text{future}}$) over a fixed horizon (30s) with active lead-time countdowns.