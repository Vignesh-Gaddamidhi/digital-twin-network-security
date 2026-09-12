# Day 100: Logistic Regression Baseline Model

## 1. Why Logistic Regression?
Logistic Regression serves as the foundational baseline classifier for network behavior classification. It is computationally lightweight, completely transparent, resistant to overfitting on small datasets when properly regularized, and produces calibrated probability estimates through the sigmoid function:
$$P(Y = 1 \mid X) = \frac{1}{1 + e^{-(\beta_0 + \sum_{j=1}^{20} \beta_j X_j)}}$$

## 2. Input Features & Target
- **Input Matrix $X$ (20 Features):** Standardized telemetry metrics including `packet_rate`, `bytes`, `bytes_per_second`, `connection_frequency`, `port_22_ratio`, `port_53_ratio`, `port_80_ratio`, `port_443_ratio`, `port_other_ratio`, `unique_destination_ports`, `flow_duration`, `tcp_ratio`, `udp_ratio`, `icmp_ratio`, `failed_connections`, `failed_connection_rate`, `dns_queries`, `dns_frequency`, `destination_diversity`, and `unique_destination_ratio`.
- **Target $y$:** Binary network security label (`NORMAL` $\to 0$, `ANOMALOUS` $\to 1$).

## 3. Model Parameters
- `solver`: `lbfgs`
- `penalty`: `l2`
- `C`: `1.0` (Inverse of regularization strength)
- `max_iter`: `500`
- `class_weight`: `balanced` (Adjusts weights inversely proportional to class frequencies)
- `random_state`: `42`

## 4. Decision Threshold Analysis
- **Default (0.50 Threshold):** Standard balance between precision and recall.
- **Lower Threshold (0.35 Threshold):** Prioritizes detection sensitivity. In high-risk environments, lowering the decision threshold catches more attacks (reducing False Negatives) at the acceptable expense of investigating additional False Positives.

## 5. Limitations
- **Linear Decision Boundary:** Incapable of modeling complex non-linear feature interactions (such as non-linear relationships between `flow_duration` and `packet_rate` during stealthy beaconing).
- **Outlier Sensitivity:** While $L_2$ regularization mitigates severe parameter explosion, massive extreme bursts can tilt linear coefficients without non-linear partition bounds.