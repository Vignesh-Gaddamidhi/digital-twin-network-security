# Day 19: MITRE ATT&CK Framework Architecture

## 1. Taxonomic Hierarchy
- **Tactics:** High-level adversary objectives (14 categories across the cyber kill chain). Answers *what* the attacker wants to accomplish.
- **Techniques:** Technical mechanisms employed to achieve a tactic. Answers *how* the adversary executes the action.
- **Sub-Techniques:** Detailed operational variations of a technique.
- **Procedures:** Specific software configurations, scripts, command strings, or packet sequences used in real engagements.

## 2. Evidence & Confidence Formulation
A detection layer should not declare an attack solely on an isolated signal. Confidence is computed based on telemetry richness:
$$\text{Confidence} = \min\left(1.0, \, w_{\text{sig}} + w_{\text{rate}} + w_{\text{state}} + w_{\text{ctx}}\right)$$
Where:
- $w_{\text{sig}}$: Presence of deterministic signature payload match ($+0.4$)
- $w_{\text{rate}}$: Anomaly rate surge ($+0.2$)
- $w_{\text{state}}$: Verified session establishment or response ($+0.2$)
- $w_{\text{ctx}}$: CVE/Exposure context on target asset ($+0.2$)