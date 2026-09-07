# Day 26: Attack Surface to Dynamic Risk Integration

## 1. Mathematical Risk Coupling
The Digital Twin computes the composite risk of an asset by coupling its attack surface, exposure tier, and active vulnerability states:

$$\text{Composite Risk} = \left( \frac{\text{Criticality} \times \text{MaxCVSS}_{\text{OPEN}}}{10} \right) \times E_{\text{Tier}} \times P(\text{Threat}) \times (1.0 - M_{\text{Controls}})$$

Where:
- $\text{MaxCVSS}_{\text{OPEN}}$: Evaluates only vulnerabilities with status `OPEN`. A vulnerability transitioned to `MITIGATED` or `PATCHED` reduces this factor immediately.
- $E_{\text{Tier}}$: Exposure multiplier derived from network placement (`EXTERNAL` $= 1.0$, `DMZ` $= 0.8$, `INTERNAL` $= 0.3$).
- $M_{\text{Controls}}$: Deduction for active firewall rules ($0.1$ per matching rule, max $0.4$).