# Day 106: Advanced Attack Prediction Architecture

## 1. Mathematical Distinction: Threat Probability vs. Category Confidence

In production network security, **Threat Probability** and **Category Confidence** must never be conflated:

1. **Threat Probability ($P_{\text{threat}} \in [0.0, 1.0]$):**
   - The binary posterior probability that an observation $X$ belongs to the malicious/threat distribution:
     $$P_{\text{threat}} = P(Y = \text{ANOMALOUS} \mid X)$$
   - Answers: *"Is an attack occurring?"*

2. **Category Confidence ($\text{Conf}_k \in [0.0, 1.0]$):**
   - The conditional categorical softmax probability assigned to the most likely attack category $k$ among candidate classes $\mathcal{C}$:
     $$\text{Conf}_k = \max_{j \in \mathcal{C}} P(\text{Category} = c_j \mid X, Y = \text{ANOMALOUS})$$
   - Answers: *"Given that an attack is detected, how certain is the model that it matches signature $c_k$?"*

**Example:**
A flood of $800{,}000$ bytes/sec might yield:
- **Threat Probability = 96%** (definitive anomaly compared to baseline normal traffic).
- **Category Confidence = 62%** (uncertainty whether the volumetric burst represents a SYN flood `DOS_LIKE` or high-throughput `EXFILTRATION_LIKE`).

## 2. Contextual Risk Formulation
The risk engine converts statistical likelihood and asset exposure into an actionable operational severity:
$$\text{RiskScore} = \min\left(100.0, \left(P_{\text{threat}} \times 40\right) + \left(\text{Conf} \times 20\right) + \left(\text{Severity}_{\text{category}} \times 20\right) + \left(\text{Criticality}_{\text{device}} \times 20\right)\right)$$

| Risk Score Range | Risk Level | SOC Action |
|---|---|---|
| $0.0 \le \text{Score} < 30.0$ | `LOW` | Routine informational audit. |
| $30.0 \le \text{Score} < 60.0$ | `MEDIUM` | Automated packet logging, elevated anomaly watch. |
| $60.0 \le \text{Score} < 85.0$ | `HIGH` | Immediate analyst alert, dynamic ACL rate-limiting. |
| $85.0 \le \text{Score} \le 100.0$ | `CRITICAL` | Automated host quarantine, core firewall isolation. |

## 3. Prediction Lifecycle State Machine
- `PENDING`: Initial telemetry received, awaiting feature extraction.
- `PREDICTED`: Model generated raw output tensors.
- `HIGH_CONFIDENCE`: Model confidence $\ge \tau_{\text{high}}$ ($0.80$).
- `LOW_CONFIDENCE`: Model confidence $< \tau_{\text{high}}$, requires human review or fallback rules.
- `REJECTED`: Telemetry out-of-distribution or schema validation failure.
- `ERROR`: Pipeline execution failure.