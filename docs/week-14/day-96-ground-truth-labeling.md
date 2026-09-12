# Day 96: Ground-Truth Labeling & Multi-Class Strategy

## 1. Labeling Taxonomy & Target Distinction

### Binary Classification Target (`binary_label`)
- `NORMAL` (Negative Class / 0)
- `ANOMALOUS` (Positive Class / 1)

### Multiclass Classification Target (`multiclass_label`)
- `NORMAL`
- `PORT_SCAN`
- `BRUTE_FORCE_LIKE`
- `DOS_LIKE`
- `DNS_ANOMALY`
- `BEACONING`
- `LATERAL_MOVEMENT_LIKE`
- `EXFILTRATION_LIKE`

### Architectural Decoupling: `scenario_label` vs. `model_label`
- **`scenario_label`:** Physical ground-truth origin (e.g., `SCN-PORTSCAN-001`, `BACKGROUND_NORMAL`, `SURICATA_ALERT_20010`).
- **`model_label`:** The categorical class target (`multiclass_label`) or binary target (`binary_label`) provided to loss functions during model training.

## 2. Label Provenance & Confidence Scoring
- **`DETERMINISTIC_SCENARIO` ($C = 1.00$):** Synthetic attacks from Phase 8 scenario orchestrators with verified execution boundaries.
- **`RULE_BASED_DETECTION` ($C = 0.85$):** Phase 10 security pipeline detections with statistical Z-score evidence.
- **`IDS_UNVERIFIED` ($C = 0.70$):** Real-world/raw Suricata alerts without confirmed exploit verification.
- **`BENIGN_BASELINE` ($C = 0.99$):** Normal synthetic baseline traffic.

## 3. Label Leakage Prevention Invariants
The feature engineering extraction pipeline guarantees that:
- Neither `scenario_id`, `scenario_label`, `alert_name`, `signature`, nor `detection_type` are included in the predictor matrix $X$.
- Only topological transport and behavioral metrics (`packet_rate`, `bytes`, `port_*_ratio`, `flow_duration`, `dns_frequency`, etc.) are exposed as inputs.