# Day 118: Temporal Convolutional Model (TCN) & Early-Warning Engine

## 1. Temporal 1D Convolution (TCN) Formulation
While recurrent networks (LSTM, GRU) process inputs sequentially ($t_1 \to t_2 \to \dots \to t_T$), a 1D Temporal Convolution evaluates sequence filters across all time steps in parallel:
$$y_t = \sum_{k=0}^{K-1} f_k \cdot x_{t - d \cdot k}$$
- **Parallel Inference:** Forward passes do not suffer from sequential recurrent unrolling bottlenecks.
- **Receptive Field:** Dilations $d \in \{1, 2\}$ allow a small kernel ($K=3$) to view the full sliding window ($T=5$).

## 2. Early-Warning State Machine
The engine classifies threats into 5 operational levels:
- `NO_WARNING`: $P_{\text{threat}} < 0.40$ (Benign traffic).
- `WATCH`: $0.40 \le P_{\text{threat}} < 0.65$ (Minor volatility detected).
- `EARLY_WARNING`: $0.65 \le P_{\text{threat}} < 0.85$ (Escalating trajectory confirmed in pre-impact stage).
- `HIGH_CONFIDENCE_WARNING`: $P_{\text{threat}} \ge 0.85$ (Critical impending impact detected).
- `IMPACT_STAGE`: System is actively experiencing volumetric disruption or host saturation.

## 3. Anti-Flooding De-duplication Protocol
To avoid alert fatigue in SOC operations:
1. When a warning state is triggered, an `EarlyWarningRecord` is created with a unique `warningId`.
2. Subsequent high-threat predictions for the same device/source during the `cooldownSeconds` window (default: $30\text{s}$) update the active warning record (`lastUpdatedAt`, `consecutiveDetections`, `peakThreatProbability`), rather than broadcasting redundant alerts.