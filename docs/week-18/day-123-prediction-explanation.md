# Day 123: Prediction Explanation Engine & Factual Evidence Composition

## 1. The Factual Integrity Principle
In automated security triage, hallucinations or over-extrapolations degrade operational trust:
- **Prohibited:** Generating speculative narratives (e.g. *"A rogue APT group deployed an automated port-scanner targeting subnet 10.0.0.0/24"*).
- **Enforced:** Translating empirical mathematical deviations into factual statements (e.g. *"Connection frequency increased by +3.1x over baseline, which contributed +0.31 toward the PORT_SCAN prediction"*).

## 2. Explanation Composition Architecture
1. **Feature Interpreters:** Maps each feature $x_j$ and its contribution $\phi_j$ to a declarative clause.
2. **Directional Triage:**
   - **Positive Contributors ($\phi_j > 0$):** Explain why the risk elevated.
   - **Negative Contributors ($\phi_j < 0$):** Explain mitigating factors that dampened the score.
3. **Multi-Tier Reporting:**
   - **Executive / Short:** Rapid situational awareness.
   - **Analyst / Detailed:** Complete narrative rationale.
   - **Engineering / Technical:** Tabular numeric attribution matrix.

## 3. Mandatory Model Limitations Disclaimer
Machine learning explanations describe model decision boundaries, not physical reality. Every explanation object must state:
> *"This explanation describes model behaviour and does not prove that an attack occurred."*