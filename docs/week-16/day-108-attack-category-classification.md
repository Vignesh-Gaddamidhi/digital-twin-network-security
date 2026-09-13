# Day 108: Multi-Class Attack Category Classification

## 1. Mathematical Formulation
Multi-class attack classification models the conditional probability distribution over $K = 8$ mutually exclusive threat categories given the 20-dimensional normalized feature vector $\mathbf{x} \in \mathbb{R}^{20}$:
$$P(Y = c_k \mid \mathbf{x}) = \frac{\exp(z_k)}{\sum_{j=0}^{K-1} \exp(z_j)}$$
where $z_k$ represents the unnormalized logit score for class $k$.

## 2. Canonical Class Mapping
| Class ID | Target Label | Telemetry Characteristic |
|---|---|---|
| 0 | `NORMAL` | Standard baseline flow rates, balanced protocol ratios. |
| 1 | `PORT_SCAN` | High unique destination ports, elevated `port_other_ratio`. |
| 2 | `BRUTE_FORCE_LIKE` | High failed connection counts, port 22/80 targets. |
| 3 | `DOS_LIKE` | Extreme packet rate ($>200\text{ pkts/s}$), short flow duration. |
| 4 | `DNS_ANOMALY` | High `dns_queries` and `dns_frequency` on UDP port 53. |
| 5 | `BEACONING` | Periodic inter-arrival times, low byte jitter. |
| 6 | `LATERAL_MOVEMENT_LIKE` | Elevated internal destination diversity, high SMB/RPC/SSH. |
| 7 | `EXFILTRATION_LIKE` | Asymmetric byte ratio, large persistent outbound streams. |

## 3. Threat Probability vs. Category Confidence Invariant
- **Threat Probability ($P_{\text{threat}}$):** Answers *"Is an attack taking place?"* Derived from the binary classifier or $1.0 - P(\text{NORMAL})$.
- **Category Confidence ($\text{Conf}$):** Answers *"Which threat signature does it best resemble?"* Defined as:
  $$\text{Conf} = \max_{k \in \{1, \dots, K-1\}} P(Y = c_k \mid \mathbf{x})$$
- These metrics are strictly decoupled. A flow may exhibit $87\%$ threat probability with $91\%$ category confidence toward `PORT_SCAN`.