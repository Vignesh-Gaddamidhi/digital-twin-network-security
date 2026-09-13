# Day 120: Explainable AI (XAI) Architecture & Fundamentals

## 1. The Need for XAI in Cyber Digital Twins
Traditional machine learning outputs a bare probability scalar:
$$P(Y = \text{THREAT} \mid \mathbf{x}) = 0.87$$

In high-assurance security operations, automated mitigation (e.g. host isolation or interface zero-routing) requires defensible evidence to prevent disruptive false positives. XAI bridges the gap between raw numeric probabilities and operational triage by providing transparent feature attributions and causal explanations.

## 2. Multi-Level Explanation Hierarchy
1. **Level 1 (Global Importance):**
   Ranks general feature influence across the entire dataset:
   $$\mathcal{I}_{\text{global}} = [f_{(1)}, f_{(2)}, \dots, f_{(M)}]$$
2. **Level 2 (Local Additive Attribution):**
   Decomposes a specific inference score into additive contributions relative to the training expectation:
   $$\hat{f}(\mathbf{x}) = \phi_0 + \sum_{j=1}^M \phi_j(\mathbf{x})$$
   - $\phi_j > 0$: Escalating feature contribution (pushes prediction toward THREAT).
   - $\phi_j < 0$: Mitigating feature contribution (pushes prediction toward BENIGN).
3. **Level 3 (Human-Readable Evidence Synthesis):**
   Maps quantitative attributions into structured, natural language analyst rationales:
   > *"Threat probability elevated to 87.0% primarily because connection frequency (+0.31) and destination diversity (+0.24) deviated significantly from baseline patterns."*

## 3. Explanation Lifecycle States
- `PENDING`: Inference completed; explanation generation queued.
- `GENERATED`: Attribution and natural language reasoning computed successfully.
- `PARTIAL`: Attribution computed, but evidence synthesis degraded or incomplete.
- `FAILED`: Feature dimension mismatch or explanation calculation failure trapped without crashing the Digital Twin.