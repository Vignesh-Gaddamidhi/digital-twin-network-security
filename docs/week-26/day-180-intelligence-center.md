# Day 180: Security Intelligence Center Architecture

## 1. Intelligence Pipeline Overview
The Intelligence Center exposes the analytical models and telemetry engines built in Weeks 12–20:

[NetFlow Ingestion] ──> [Traffic Analytics] ──> [Threat Timeline]
│
▼
[SHAP Waterfall Explanation] <── [XAI] <── [ML Model Inference]


## 2. Supervised & Temporal Model Taxonomy
- **Classical ML Classifiers**: Logistic Regression, Decision Tree, Random Forest, SVM, XGBoost (CIC-IDS2017 feature baseline).
- **Deep Temporal Models**: LSTM, GRU, Hybrid Temporal Ensemble (sliding windows with 30s prediction horizons).

## 3. Explainable AI (SHAP Formulation)
Output decomposes prediction probabilities via Shapley values:
$$P(\text{Threat}) = \phi_0 + \sum_{i=1}^{M} \phi_i$$
- $\phi_0$: Baseline expectation probability ($0.12$).
- $\phi_i > 0$: Anomaly amplification drivers (e.g. connection frequency, port diversity).
- $\phi_i < 0$: Benign dampening factors (e.g. standard user-agent, expected maintenance window).