# Day 127: Risk Scoring Architecture & Factor Definitions

## 1. Threat vs. Risk Decoupling
Threat represents the likelihood of malicious behavior. Risk represents the expected potential loss to the organization.
- Threat Probability $P_{\text{threat}} \in [0.0, 1.0]$: Derived from Phase 13 & 14 ML inference.
- Asset Criticality $C_{\text{asset}} \in [0.2, 1.0]$: Operational value of the target node in the Digital Twin topology.
- Vulnerability Score $V_{\text{asset}} \in [0.2, 1.0]$: Known exploitability status of services bound to the target device.
- Attack Impact $I_{\text{attack}} \in [0.2, 1.0]$: Inherent potential consequence of the predicted attack category.

## 2. Mathematical Normalization
All categorical dimensions map to normalized weights:
- `VERY_LOW` / `NONE`: 0.20
- `LOW`: 0.40
- `MEDIUM`: 0.60
- `HIGH`: 0.80
- `CRITICAL`: 1.00

Continuous calculation:
$$\text{RiskRaw} = P_{\text{threat}} \times C_{\text{asset}} \times V_{\text{asset}} \times I_{\text{attack}}$$
$$\text{RiskScore} = \text{RiskRaw} \times 100.0$$

## 3. Defensive Invariants
- Threat probabilities $< 0.0$ or $> 1.0$ are rejected with `ValidationError`.
- Missing factors immediately transition the assessment status to `INVALID` or `FAILED` without crashing the simulation engine.