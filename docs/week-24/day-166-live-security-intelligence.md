# Day 166: Live Threats, Alerts, Predictions, Risk, Attack Paths & Early Warnings

## 1. The Reactive & Predictive Intelligence Chain
Security intelligence executes as a strictly verified, un-bypassed pipeline:
[Simulated / Live Telemetry]
│
▼
[IDS / Zeek Detection] ──────> Emits THREAT_UPDATE (Timeline & Badges)
│
▼
[ML & Time-Series]   ──────> Emits PREDICTION_UPDATE (P_current vs P_future)
│
▼
[SHAP XAI Engine]   ──────> Updates "Why?" factor explanations
│
▼
[Risk Engine]      ──────> Emits RISK_UPDATE: P(threat) * C(asset) * V(vuln) * I(impact)
│
▼
[Attack Path Graph]   ──────> Emits ATTACK_PATH_UPDATE & triggers 3D spline glow
│
▼
[Security Alert Hub]  ──────> Emits ALERT_UPDATE (SOAR / Incident Queue)


## 2. Invariants & Guardrails
- **Dual Probability Separation**: $P(\text{threat})_{\text{current}}$ represents real-time classification probability; $P(\text{threat})_{\text{future}}$ represents predictive forecasting over a sliding window with lead time ($T_{\text{lead}}$). They are never conflated into a single metric.
- **Canonical Formula Rule**: Frontend renders the Risk Engine calculation exclusively:
  $$RiskScore = P_{threat} \times Criticality_{asset} \times Vuln_{factor} \times Impact_{attack}$$
- **Authentic State Transitions**: `COMPROMISED` and `ISOLATED` states are only visually applied when the canonical Digital Twin confirms the state mutation.