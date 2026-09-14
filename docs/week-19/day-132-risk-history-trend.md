# Day 132: Risk History, Aggregation, Trend & Digital Twin Integration

## 1. Directional Risk Trend Formulation
Given an observation window of $K \ge 3$ consecutive risk scores $S = [s_1, s_2, \dots, s_K]$:
1. **Delta Velocity:** $\Delta s = s_K - s_1$
2. **Normalized Rate:** $\frac{\Delta s}{K - 1}$
3. **Volatility Metric:** $\sigma_S = \sqrt{\frac{1}{K}\sum_{i=1}^K (s_i - \bar{s})^2}$

Classification Rules:
- `INCREASING`: $\Delta s \ge +10.0$ and consistent positive slope.
- `DECREASING`: $\Delta s \le -10.0$ and consistent negative slope.
- `STABLE`: $|\Delta s| < 10.0$ and $\sigma_S < 5.0$.
- `VOLATILE`: Rapid directional sign alternations or $\sigma_S \ge 15.0$ without monotonic drift.
- `UNKNOWN`: Window length $K < 3$.

## 2. Risk State Transitions & Event Emission
Ordinal weights: $\text{LOW}=1, \text{MEDIUM}=2, \text{HIGH}=3, \text{CRITICAL}=4$.
- **Escalation ($\text{Rank}_t > \text{Rank}_{t-1}$):** Triggers `RISK_LEVEL_INCREASED`. If new level $\ge \text{HIGH}$, emits `HIGH_RISK_REACHED` or `CRITICAL_RISK_REACHED`.
- **De-escalation / Recovery ($\text{Rank}_t < \text{Rank}_{t-1}$):** Triggers `RISK_LEVEL_DECREASED`, marking asset remediation.
- **Spike Trigger:** Score delta $s_t - s_{t-1} \ge 25.0$ points triggers `RISK_SCORE_SPIKE`.