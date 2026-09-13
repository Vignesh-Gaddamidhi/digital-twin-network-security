# Day 115: Time-Series Feature Engineering & Registry

## 1. Temporal Feature Formulation
Temporal feature engineering transforms static snapshot data into dynamic trajectory signals:
1. **Rolling Statistics ($\tau \in \{3, 5\}$):**
   - **Rolling Mean ($\mu_\tau$):** Measures local moving baseline level.
   - **Rolling Standard Deviation ($\sigma_\tau$):** Measures local volatility and burstiness.
   - **Rolling Min / Max / Median:** Robust boundary and distribution trackers.
2. **First-Order Differencing (Rate of Change):**
   $$\Delta x_t = x_t - x_{t-1}$$
3. **Percentage Change ($\% \Delta x_t$):**
   $$\% \Delta x_t = \frac{x_t - x_{t-1}}{\max(\epsilon, |x_{t-1}|)} \times 100\%, \quad \epsilon = 10^{-5}$$
4. **Trend Disambiguation Engine:**
   - **`VOLATILE`:** If $\text{CV} = \frac{\sigma_\tau}{\mu_\tau + \epsilon} \ge 0.50$ and alternating derivative signs occur.
   - **`INCREASING`:** If $\Delta x_t > \delta$ (where $\delta$ is feature-specific sensitivity).
   - **`DECREASING`:** If $\Delta x_t < -\delta$.
   - **`STABLE`:** If $|\Delta x_t| \le \delta$.

## 2. Temporal Feature Coverage Matrix
| Base Feature | Lags ($t-1, t-2$) | Rolling ($\mu, \sigma$) | Differencing ($\Delta X, \%\Delta$) | Trend Class |
|---|---|---|---|---|
| `packet_rate` | Yes | Yes ($w=3, 5$) | Yes | Yes |
| `bytes` | Yes | Yes ($w=3, 5$) | Yes | Yes |
| `connection_frequency` | Yes | Yes ($w=3$) | Yes | Yes |
| `flow_duration` | Yes | Yes ($w=3$) | Yes | Yes |
| `failed_connections` | Yes | Yes ($w=3$) | Yes | Yes |
| `dns_frequency` | Yes | Yes ($w=3$) | Yes | Yes |
| `destination_diversity`| Yes | Yes ($w=3$) | Yes | Yes |
| `port_distribution` | Yes | Yes ($w=3$) | Yes | Yes |
| `protocol_distribution`| Yes | Yes ($w=3$) | Yes | Yes |

## 3. Missing Value & Boundary Backfilling Policy
- At initial steps $t < k$ where lag $t-k$ does not yet exist, backward replication (backfilling with $x_0$) is enforced to avoid `NaN` or pipeline collapse.
- Rolling windows for $t < w$ compute statistics over available historical steps $[x_0, \dots, x_t]$ without zero padding.