# Day 176: Enterprise SOC/SIEM Architecture & Navigation Foundation

## 1. Executive Console Architecture
Phase 22 organizes Weeks 1–25 intelligence into a unified Security Operations Center workflow. Rather than disjointed pages, all views consume a synchronized global context:

[Threat Alert] ➔ [Incident] ➔ [Forensic Investigation] ➔ [ML Prediction + XAI] ➔ [Attack Path] ➔ [Remediation Playbook]


## 2. Navigation Taxonomy (18 Enterprise Modules)
1. **Security Operations**:
   - `Dashboard` (`/`): Executive posture, KPI ribbons, threat gauges, and simulation sandbox.
   - `Network Twin` (`/network-twin`): Subnet view (DMZ, Corp, DB) with 2D topology & 3D Three.js viewports.
   - `Threat Detection` (`/threat-detection`): IDS event streamer, Suricata/Zeek logs, and packet inspector.
   - `Attack Simulation` (`/attack-simulation`): Synthetic scenario launcher with interactive telemetry console.
   - `Risk Analysis` (`/risk-analysis`): Asset risk matrix ($P \times C \times V \times I$) and vulnerability tracking.
   - `Attack Paths` (`/attack-paths`): Multi-hop blast radius explorer and reachability graph.
   - `Predictions` (`/predictions`): Classification probabilities, confidence scores, and dual-horizon forecasts.
   - `Alerts` (`/alerts`): Prioritized alerts queue with severity badges and triage statuses.
   - `Incidents` (`/incidents`): Correlated multi-alert incidents and SOAR remediation workflows.
2. **Intelligence**:
   - `ML Models` (`/intelligence/ml-models`): Supervised model benchmarks, confusion matrices, and ROC-AUC metrics.
   - `XAI` (`/intelligence/xai`): SHAP feature contribution waterfall and explainability explanations.
   - `Threat Timeline` (`/intelligence/threat-timeline`): Chronological microsecond threat sequence ledger.
   - `Traffic Analytics` (`/intelligence/traffic-analytics`): NetFlow streaming rates, protocol distribution, and bandwidth graphs.
3. **Governance & Admin**:
   - `Reports` (`/governance/reports`): Executive posture summaries, compliance audits, and JSON/PDF exports.
   - `Audit Logs` (`/governance/audit-logs`): Tamper-evident 9-stage forensic response audit ledger.
   - `Users` (`/governance/users`): Authorized operator access lists and credentials management.
   - `Roles` (`/governance/roles`): RBAC matrix (`ADMIN`, `SECURITY_LEAD`, `SOC_ANALYST`, `AUDITOR`, `VIEWER`).
   - `Settings` (`/governance/settings`): Gateway WebSocket configuration and simulation parameters.

## 3. Universal Global Search & Multi-Entity Query Index
A centralized omni-search input (`Cmd/Ctrl + K`) indexes across 8 domain entities:
- `DEVICE`, `ALERT`, `INCIDENT`, `PREDICTION`, `THREAT`, `ATTACK_PATH`, `SIMULATION`, `AUDIT_ENTRY`.