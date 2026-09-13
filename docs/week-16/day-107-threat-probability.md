# Day 107: Calibrated Threat Probability Engine

## 1. Probability vs. Classification Threshold
In machine learning intrusion detection, binary classification is composed of two independent layers:
1. **Continuous Scoring / Posterior Likelihood:**
   $$P_{\text{threat}} = P(Y = \text{ANOMALOUS} \mid \mathbf{x}) \in [0.0, 1.0]$$
2. **Decision Boundary Rule:**
   $$\text{Class}(P_{\text{threat}}, \tau) = \begin{cases} \text{THREAT}, & \text{if } P_{\text{threat}} \ge \tau \\ \text{NORMAL}, & \text{if } P_{\text{threat}} < \tau \end{cases}$$

Changing the decision threshold $\tau$ (e.g. lowering from $0.50$ to $0.35$ to improve recall) changes the categorical assignment, but does **not** alter the underlying empirical threat probability ($87\%$).

## 2. Multi-Model Probability Normalization
- **Logistic Regression / Decision Tree / Random Forest / XGBoost:** Natively provide calibrated softmax/sigmoid posteriors:
  $$P_{\text{threat}} = \text{predict\_proba}(\mathbf{x})[:, 1]$$
- **Support Vector Machine (SVM):** If Platt scaling is active via `CalibratedClassifierCV`, utilizes cross-validated logistic sigmoid probabilities. If raw `decision_function` signed distance $d(\mathbf{x})$ is used:
  $$P_{\text{threat}} = \frac{1}{1 + e^{-d(\mathbf{x})}}$$

## 3. Probability Validation Invariants
The engine rejects and flags any prediction where:
- $P_{\text{threat}} < 0.0$ or $P_{\text{threat}} > 1.0$
- $P_{\text{threat}}$ is `NaN` or `None`
- Sum of class probabilities $\sum P(y_k) \not\approx 1.0$