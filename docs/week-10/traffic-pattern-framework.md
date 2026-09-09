# Day 67: Generic Traffic Pattern Framework

## 1. Principles
The Traffic Pattern Engine generates synthetic wire telemetry mimicking attack-like distributions without weaponized payloads.

## 2. Seven Supported Pattern Waveforms
1. `PERIODIC`: Emits packets at fixed intervals $\Delta t = 1 / \text{rate}$.
2. `BURST`: Concentrated surges within discrete microsecond/second windows followed by idle periods.
3. `REPEATED`: High-frequency repeated transactions hitting identical socket tuples.
4. `SEQUENTIAL`: Systematic sequential progression across ports, IPs, or packet sequence IDs.
5. `RANDOMIZED`: Uniformly distributed pseudo-random port or payload variations.
6. `GRADUAL_INCREASE`: Linear ramp-up scaling from a baseline rate to peak saturation.
7. `GRADUAL_DECREASE`: Controlled ramp-down decelerating from peak volume to baseline.

## 3. Timing & Jitter Control
$$\text{Timestamp}_i = t_0 + i \cdot \Delta t + \text{jitter}_i, \quad \text{where } \text{jitter}_i \in [-\text{jitterMax}, +\text{jitterMax}]$$
All jitter and port selections use explicit seed instances (`random.Random(seed)`).