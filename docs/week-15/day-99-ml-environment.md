# Day 99: ML Environment Setup & Baseline Classification Pipeline

## 1. Classification Framing
Network behavior classification is framed primarily as binary anomaly detection:
- Negative Class ($y = 0$): `NORMAL` baseline traffic (HTTP, DNS, SSH, background flows).
- Positive Class ($y = 1$): `ANOMALOUS` threat traffic (Reconnaissance, Brute Force, DoS, Exfiltration, Beaconing).

Multiclass scenario labels (`PORT_SCAN`, `DOS_LIKE`, etc.) remain preserved in dataset metadata for multiclass extensions.

## 2. Feature Matrix $X$ vs. Target $y$
- Feature matrix $X \in \mathbb{R}^{N \times 20}$: Strictly standardized numerical features derived from Day 95–98 transformations.
- Target vector $y \in \{0, 1\}^N$: Encoded binary ground truth.
- Zero Leakage Invariant: Non-feature fields (`sampleId`, `timestamp`, `sourceDevice`, `destinationDevice`, `scenario_label`, `multiclass_label`, `metadata`) are excluded from $X$.

## 3. Common Model Interface (`BaseAttackClassifier`)
All 5 baseline classifiers inherit from `BaseAttackClassifier`:
1. `train(X, y)`
2. `predict(X)`
3. `predict_proba(X)`
4. `evaluate(X, y)`
5. `save(path)` / `load(path)`