# Day 116: Baseline LSTM Sequence Attack-Prediction Model

## 1. Network Architecture
To ensure real-time latency (<15 ms) and minimal memory footprint, a compact single-layer recurrent architecture is adopted:
- **Input Dimension:** $[N, T=5, D=16]$
- **Recurrent Layer:** LSTM with 32 hidden units, tanh activation, and recurrent sigmoid.
- **Regularization:** Dropout ($p=0.20$) on hidden states.
- **Classification Head:** Dense projection ($32 \to 16 \to 1$) with Sigmoid activation.
- **Loss Function:** Binary Cross-Entropy (Log Loss).
- **Optimization:** Adam ($\eta = 0.005$, $\beta_1 = 0.9, \beta_2 = 0.999$).

## 2. Early-Warning Lead Time Metric
In addition to standard statistical metrics (Accuracy, Precision, Recall, F1, ROC-AUC), temporal models are evaluated on operational timeliness:
$$\Delta t_{\text{lead}} = t_{\text{impact\_onset}} - t_{\text{first\_early\_warning}}$$

Where:
- $t_{\text{impact\_onset}}$: The timestamp when telemetry exceeds physical operational failure thresholds (e.g. saturation of interface bandwidth or crash of service).
- $t_{\text{first\_early\_warning}}$: The earliest timestamp where the sequence model outputs $P(\text{Future Threat}) \ge \tau_{\text{warn}}$ ($0.50$).