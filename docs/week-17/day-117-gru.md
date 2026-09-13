# Day 117: GRU Attack-Prediction Model & LSTM vs. GRU Comparison

## 1. Algorithmic Overview: Gated Recurrent Unit
The GRU streamlines recurrent state management by eliminating the separate cell memory state $C_t$:
- **Update Gate ($z_t$):** Governs the interpolation between the previous state $h_{t-1}$ and candidate state $\tilde{h}_t$.
- **Reset Gate ($r_t$):** Determines how much of the past hidden trajectory influences the candidate state.

$$\begin{aligned}
z_t &= \sigma(W_z x_t + U_z h_{t-1} + b_z) \\
r_t &= \sigma(W_r x_t + U_r h_{t-1} + b_r) \\
\tilde{h}_t &= \tanh(W_h x_t + U_h (r_t \odot h_{t-1}) + b_h) \\
h_t &= (1 - z_t) \odot h_{t-1} + z_t \odot \tilde{h}_t
\end{aligned}$$

## 2. Controlled Comparison Protocol
Both models are evaluated over the identical normalized sliding-window sequences ($N, T=5, D=16$):
1. **Detection Performance:** Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix.
2. **Operational Timeliness:** Early-warning lead time ($\Delta t_{\text{lead}} = t_{\text{impact}} - t_{\text{warning}}$).
3. **Computational Efficiency:** Training duration, per-sequence inference latency, parameter count, and artifact disk footprint.