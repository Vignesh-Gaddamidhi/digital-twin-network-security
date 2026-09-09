# Day 69: Severity & Scenario Classification Engine

## 1. Principles
- **Simulation Classifications:** Represents the theoretical danger level of simulated tactics, not an actual compromise declaration.
- **Dynamic Risk Evaluation:**
  $$\text{Risk Score} = \text{Likelihood} \times \text{Impact}$$
- Evaluates target asset criticality (e.g. database server in Internal Zone vs. edge proxy in DMZ) to modulate composite impact.

## 2. Baseline Scenario Severity Matrix
| Scenario Category | Initial Severity | Base Likelihood | Base Impact |
|---|---|---|---|
| `PORT_SCAN` | `MEDIUM` | 0.80 | 4.0 |
| `BRUTE_FORCE` | `HIGH` | 0.65 | 7.5 |
| `DOS` | `HIGH` | 0.70 | 8.0 |
| `SUSPICIOUS_DNS` | `MEDIUM` | 0.50 | 5.5 |
| `BEACONING` | `HIGH` | 0.60 | 7.0 |
| `LATERAL_MOVEMENT` | `HIGH` | 0.45 | 8.5 |
| `DATA_EXFILTRATION` | `CRITICAL`| 0.40 | 10.0 |

## 3. Score Ranges
- `0.0 - 24.9`: **LOW**
- `25.0 - 49.9`: **MEDIUM**
- `50.0 - 74.9`: **HIGH**
- `75.0 - 100.0`: **CRITICAL**