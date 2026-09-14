# Day 146: Attack Prediction & XAI Explanation Panel

## 1. Dual Threat Horizon Formulation
- **Instantaneous Threat ($P_{\text{current}}$):** Evaluated over current feature vector $x_t \in \mathbb{R}^d$.
- **Predictive Threat ($P_{\text{future}}$):** Evaluated by GRU/LSTM recurrent models over sliding window $X_{t-W:t}$ projecting ahead by lead time $\Delta t$.

## 2. Early-Warning State Machine
- `NO_WARNING`: $P_{\text{future}} < 0.35$
- `WATCH`: $0.35 \le P_{\text{future}} < 0.60$
- `EARLY_WARNING`: $0.60 \le P_{\text{future}} < 0.75$
- `HIGH_CONFIDENCE_WARNING`: $0.75 \le P_{\text{future}} < 0.90$
- `IMPACT_STAGE`: $P_{\text{future}} \ge 0.90 \land P_{\text{current}} \ge 0.80$

## 3. Explainable AI (XAI) SHAP Ingestion
Local feature contributions satisfy additive efficiency:
$$f(x) = \phi_0 + \sum_{j=1}^M \phi_j$$
Where each feature $j$ contributes positively or negatively to the predicted anomaly score.