# Day 187: Alerts, Incidents, Predictions, XAI & Risk Persistence

## 1. SOC Investigation Schema Architecture
Day 187 establishes the durable relational foundation connecting real-time detections to forensic explanations and SOAR tickets:

                  ┌───────────────┐
                  │   incidents   │
                  ├───────────────┤
                  │ incident_id   │
                  │ title         │
                  │ severity      │
                  │ status        │
                  └───────┬───────┘
                          │ (1:N)
    ┌─────────────────────┼─────────────────────┐
    ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│    alerts    │      │ risk_assess. │      │ attack_paths │
├──────────────┤      ├──────────────┤      ├──────────────┤
│ alert_id     │      │ risk_id      │      │ path_id      │
│ device_id(FK)│      │ P x C x V x I│      │ src_dev (FK) │
│ severity     │      │ risk_score   │      │ dst_dev (FK) │
└──────┬───────┘      └──────────────┘      │ path []      │
│                                    └──────────────┘
▼
┌──────────────┐
│ predictions  │ (ML Classification)
├──────────────┤
│ prediction_id│
│ threat_prob  │
└──────┬───────┘
│
▼ (1:1)
┌──────────────┐
│xai_explanat. │ (TreeSHAP Explanations)
├──────────────┤
│ base_value   │
│ shap_values  │
│ human_expl   │
└──────────────┘


## 2. Investigation Chain Invariants
1. **Durable Attribution**: An analyst querying an incident months after occurrence can inspect the exact TreeSHAP attribution and feature importance that drove the automated recommendation.
2. **Canonical Risk Metric**: The $P \times C \times V \times I$ formula is strictly computed and stored alongside the raw individual factors ($P, C, V, I$).
3. **Temporal Early Warning**: Separate temporal prediction records preserve future probabilities and early warning lead-time countdowns without overwriting current threat classifications.