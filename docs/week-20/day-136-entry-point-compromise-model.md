# Day 136: Attacker, Entry Point & Compromised Device Model

## 1. Adversary Entity Modeling
The attacker node (`ATTACKER-01`) serves as the root origin in scenario path exploration. It has no internal asset value (`assetCriticality = VERY_LOW`), resides in the `INTERNET` zone, and acts as the source for ingress edges.

## 2. Epistemic State Decoupling
To ensure simulation safety and auditability, device state is bifurcated:
- `CONFIRMED_SIMULATION_STATE`: Set deterministically by attack scenario runners (`NORMAL`, `COMPROMISED`, `ISOLATED`).
- `ML_PREDICTED_STATE`: Derived continuously from classification telemetry (`AT_RISK`, `SUSPICIOUS`).

## 3. Entry Point Prioritization Formula
Entry points are scored continuously on a $[0.0, 1.0]$ scale:
$$\text{EntryScore} = 0.25 E + 0.20 R + 0.25 V + 0.15 \left(\frac{\text{RiskScore}}{100}\right) + 0.15 P_{\text{threat}}$$
Nodes in the DMZ or Internet-facing perimeters with unpatched CVEs and active ML anomalies receive priority during path ranking.