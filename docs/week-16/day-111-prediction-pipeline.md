# Day 111: End-to-End Attack Prediction Pipeline

## 1. End-to-End Dataflow
The Day 111 pipeline integrates the complete inference cycle:
1. **Observation**: Ingests raw network telemetry (packet count, byte count, flow duration, ports, flags).
2. **Feature Extraction**: Constructs the standardized 20-dimensional normalized predictor vector $\mathbf{x} \in \mathbb{R}^{20}$.
3. **Threat Probability Evaluation**: Queries the binary classifier for continuous calibrated threat probability $P_{\text{threat}} \in [0.0, 1.0]$.
4. **Multi-Class Signature Disambiguation**: Queries the multi-class model across the 8 canonical categories.
5. **Confidence Audit**: Evaluates Shannon entropy and separation margin to assign a confidence tier (`HIGH_CONFIDENCE`, `MEDIUM_CONFIDENCE`, `LOW_CONFIDENCE`).
6. **Risk Synthesis**: Combines likelihood, category impact, device criticality, exposure, and vulnerabilities into an operational score ($[0.0, 100.0]$) and risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
7. **Digital Twin Mutation**: Updates device security state and maintains immutable historical prediction audit logs.
8. **Security Alerting**: Triggers `ML_ATTACK_PREDICTION` alerts for high-risk events.

## 2. Security State Machine Transition Invariants
- `NORMAL` $\to$ `SUSPICIOUS`: $P_{\text{threat}} \ge 0.50$ OR $\text{RiskScore} \ge 30.0$.
- `SUSPICIOUS` $\to$ `AT_RISK`: $\text{RiskLevel} \in \{\text{HIGH}, \text{CRITICAL}\}$ AND $\text{Confidence} \ge 0.70$.
- Guardrail: An ML inference output alone **never** forces a transition to `COMPROMISED`. The `COMPROMISED` state requires confirmed exfiltration execution or multi-layer correlated deterministic exploit detection.