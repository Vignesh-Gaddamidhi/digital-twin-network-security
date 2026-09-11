# Day 90: Contextual Risk Scoring & Impact Engine

## 1. Risk Formulation
The pipeline computes risk as:
$$\text{RiskScore} = \min(100.0, \text{Likelihood} \times \text{Impact} \times 10.0)$$

### A. Likelihood ($0.0 \le L \le 1.0$)
Derived from:
1. **Detection Confidence:** $C \in [0.0, 1.0]$.
2. **Detection Severity Weight:** $\text{CRITICAL}=1.0$, $\text{HIGH}=0.85$, $\text{MEDIUM}=0.65$, $\text{LOW}=0.40$.
3. **Behavioral Persistence Factor:** Recurring or repeated attempts boost likelihood by up to $+0.15$.
$$L = \min(1.0, (C \times 0.6) + (\text{SeverityWeight} \times 0.3) + \text{PersistenceBonus})$$

### B. Impact ($1.0 \le I \le 10.0$)
Derived from Digital Twin context:
1. **Asset Criticality:** `CRITICAL` (DB/Core) $\to 4.0$, `HIGH` (Web/App) $\to 3.0$, `MEDIUM` $\to 2.0$, `LOW` $\to 1.0$.
2. **Network Zone Exposure:** `EXTERNAL` $\to 1.5\times$, `DMZ` $\to 1.3\times$, `INTERNAL` $\to 1.0\times$.
3. **Vulnerability State:** Active unpatched CVEs on target boost impact by $+1.5$ to $+2.5$.
4. **Behavioral Potential Harm:** Exfiltration or RCE signatures add $+2.0$.
$$I = \min(10.0, (\text{BaseCriticality} \times \text{ExposureMultiplier}) + \text{VulnPenalty} + \text{HarmScore})$$

## 2. Risk Levels
- **`CRITICAL`:** $\text{Score} \ge 75.0$
- **`HIGH`:** $50.0 \le \text{Score} < 75.0$
- **`MEDIUM`:** $25.0 \le \text{Score} < 50.0$
- **`LOW`:** $\text{Score} < 25.0$