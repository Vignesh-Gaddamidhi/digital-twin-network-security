# Day 194: ML, Alert Distribution & Security Event Consumers

## 1. End-to-End Intelligence Pipeline Lineage
Day 194 orchestrates the multi-consumer reactive processing loop through Redis:

[Incoming NetFlow Event]
│
▼
[MLInferenceConsumer]
├── Computes Dual-Horizon Probabilities (P_curr vs P_fut)
├── Extracts TreeSHAP Feature Attributions
└── Emits PREDICTION_UPDATE
│
▼
[RiskConsumer]
├── Computes Risk = P(Threat) * C(Asset) * V(Vulnerability) * I(Impact)
└── Emits RISK_UPDATE
│
┌─────┴──────────────────────────────┐
▼                                    ▼
[AlertConsumer]                  [AttackPathConsumer]
├── Dedupes & Triages Detections ├── Traces Graph Hops (CLIENT -> WEB -> DB)
├── Persists to PostgreSQL       └── Emits ATTACK_PATH_UPDATE
└── Emits ALERT_UPDATE
│
▼ (Correlation Condition: >= 2 Alerts)
[IncidentConsumer]
├── Groups Alerts into Formal SOAR Incident Case
├── Binds Operator (Sarah Connor)
└── Broadcasts INCIDENT_UPDATE over WebSocket Gateway


## 2. Invariant Rules
1. **Model Family Integrity**: The event streaming pipeline orchestrates all 8 ML models without replacing or altering their algorithmic weights.
2. **Selective Incident Promotion**: Alerts do not become incidents automatically. A multi-alert threshold ($\ge 2$ correlated alerts sharing a `correlationId`) is enforced before escalating.
3. **Audit Immutability**: All triaged alerts and escalated incidents write to PostgreSQL asynchronously while dispatching real-time WebSocket frames without latency bottlenecks.