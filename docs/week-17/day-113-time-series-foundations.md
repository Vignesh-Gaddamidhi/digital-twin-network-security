# Day 113: Time-Series Foundations & Temporal Dynamics

## 1. The Temporal Early-Warning Premise
In static classification (Weeks 15–16), an observation of `packet_rate = 180 pkts/s` is treated identically regardless of whether it arrived from a calm steady state or an explosive exponential ramp:
- **Calm Baseline:** $175 \to 180 \to 178$ (Normal benign burst).
- **Attack Trajectory:** $20 \to 31 \to 65 \to 110 \to 180$ (Impending Volumetric DoS or Exfiltration).

Tracking sequential evolution allows detection of threat progression in its **pre-impact incubation stage** before saturation thresholds are breached.

## 2. Fixed Observation Interval ($\Delta t = 5.0\text{s}$)
To prevent aliasing and sampling distortion, all time-series features enforce a versioned interval:
$$\Delta t = 5.0\text{ seconds}$$
Telemetries within each window are aggregated, preserving chronological monotonicity ($t_1 < t_2 < t_3 < \dots$).

## 3. Mathematical Definitions of Temporal Dynamics
For continuous telemetry feature $x(t)$ sampled at discrete steps $t \in \{1, \dots, T\}$:

1. **Lag Operators:**
   $$L^k x_t = x_{t-k}, \quad k \in \{1, 2, 3\}$$

2. **First Difference (Rate of Change):**
   $$\Delta x_t = x_t - x_{t-1}$$

3. **Relative Percentage Change:**
   $$\% \Delta x_t = \frac{x_t - x_{t-1}}{\max(1e-5, |x_{t-1}|)}$$

4. **Velocity / Trend ($S_t$):**
   $$S_t = \frac{\Delta x_t}{\Delta t}$$

5. **Acceleration ($A_t$):**
   $$A_t = \frac{S_t - S_{t-1}}{\Delta t} = \frac{(x_t - x_{t-1}) - (x_{t-1} - x_{t-2})}{\Delta t^2}$$

6. **Rolling Statistics ($\tau \in \{3, 5\}$):**
   $$\mu_\tau(t) = \frac{1}{\tau} \sum_{i=0}^{\tau-1} x_{t-i}, \quad \sigma_\tau(t) = \sqrt{\frac{1}{\tau} \sum_{i=0}^{\tau-1} (x_{t-i} - \mu_\tau(t))^2}$$