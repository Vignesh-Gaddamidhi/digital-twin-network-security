# Day 130: Core Risk Calculation Engine

## 1. Multiplicative Risk Formulation
The calculation engine computes:
$$\text{Risk}_{\text{raw}} = T \times A \times V \times I$$
$$\text{Risk}_{\text{score}} = \text{Risk}_{\text{raw}} \times 100.0$$

Where:
- $T \in [0.0, 1.0]$: Threat Probability
- $A \in [0.2, 1.0]$: Asset Criticality
- $V \in [0.2, 1.0]$: Effective Vulnerability Score
- $I \in [0.2, 1.0]$: Attack Impact Score

## 2. Threshold Classification Standard
- `[0.0, 25.0)  -> LOW`
- `[25.0, 50.0) -> MEDIUM`
- `[50.0, 75.0) -> HIGH`
- `[75.0, 100.0] -> CRITICAL`

## 3. Strict Deterministic Proof Cases
- Example 1: $0.5 \times 0.4 \times 0.4 \times 0.4 = 0.032 \times 100 = 3.20$ (`LOW`)
- Example 2: $0.8 \times 0.8 \times 0.8 \times 0.8 = 0.4096 \times 100 = 40.96$ (`MEDIUM`)
- Example 3: $0.9 \times 1.0 \times 1.0 \times 1.0 = 0.9000 \times 100 = 90.00$ (`CRITICAL`)