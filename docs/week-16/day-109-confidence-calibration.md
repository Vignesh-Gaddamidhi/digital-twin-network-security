# Day 109: Prediction Confidence & Probability Calibration

## 1. Mathematical Distinction: Threat Probability vs. Category Confidence
- **Threat Probability ($P_{\text{threat}} \in [0.0, 1.0]$):**
  $$P_{\text{threat}} = P(Y = \text{ANOMALOUS} \mid \mathbf{x})$$
  Evaluates whether the telemetry is benign or hostile.
- **Category Confidence ($\text{Conf}_k \in [0.0, 1.0]$):**
  $$\text{Conf}_k = \max_{j} P(\text{Category} = c_j \mid \mathbf{x})$$
  Evaluates the conditional assignment across the $K=8$ candidate attack classes.

## 2. Confidence Tiering via Uncertainty Estimation
Confidence is assessed using two complementary metrics:
1. **Top-2 Separation Margin ($\Delta$):**
   $$\Delta = p_{(1)} - p_{(2)}$$
   Measures the distance between the top predicted class and the runner-up. Small $\Delta$ indicates ambiguity (e.g. DoS vs. Exfiltration).
2. **Normalized Shannon Entropy ($H_N$):**
   $$H(P) = -\sum_{k=1}^K p_k \log_2(p_k), \quad H_N(P) = \frac{H(P)}{\log_2(K)}$$
   $H_N \in [0.0, 1.0]$. When $H_N \to 0$, the model is decisively certain. When $H_N \to 1$, the distribution approaches a random uniform guess.

### Configurable Confidence Tiers:
- **`HIGH_CONFIDENCE`:** $\text{Conf} \ge 0.80$ AND $\Delta \ge 0.35$ AND $H_N \le 0.40$
- **`MEDIUM_CONFIDENCE`:** $\text{Conf} \ge 0.50$ AND $\Delta \ge 0.15$
- **`LOW_CONFIDENCE`:** Fails higher thresholds (e.g. multi-way ties or flat distributions).

## 3. Probability Calibration (Platt Scaling & Isotonic Regression)
A model is perfectly calibrated if:
$$P(\hat{Y} = Y \mid \hat{P} = p) = p, \quad \forall p \in [0, 1]$$

Calibration quality is measured by:
- **Brier Score:**
  $$\text{BS} = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)^2$$
- **Expected Calibration Error (ECE):**
  $$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$