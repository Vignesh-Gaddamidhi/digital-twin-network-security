# Day 114: Sliding Windows & Sequence Dataset Generation

## 1. Sliding Window Parameters
- `window_size` ($T$): Number of historical time-steps in each observation sequence (default: $10$).
- `step_size` ($S$): Stride between consecutive window starts (default: $1$).
- `prediction_horizon` ($H$): Number of future steps ahead over which threat emergence is evaluated (default: $3$).
- `min_sequence_length`: Minimum valid observations required before sequence extraction begins (default: $T + H$).

## 2. Temporal Target Formulation
For each sequence $i$ starting at index $k$:
$$\mathbf{X}_i = [\mathbf{x}_k, \mathbf{x}_{k+1}, \dots, \mathbf{x}_{k+T-1}] \in \mathbb{R}^{T \times D}$$

The ground-truth future target $y_i$ is evaluated over the future horizon slice:
$$\mathcal{H}_i = \{y_{k+T}, y_{k+T+1}, \dots, y_{k+T+H-1}\}$$
- **Binary Early Warning Target:**
  $$y_{\text{future}, i} = \begin{cases} 1, & \text{if } \exists y \in \mathcal{H}_i \text{ such that } y \ne \text{NORMAL} \\ 0, & \text{otherwise} \end{cases}$$
- **Multi-Class Future Target:** The most severe attack category present within horizon $\mathcal{H}_i$.

## 3. Strict Anti-Leakage Protocol
1. **Temporal Non-Inversion:** $t_{\text{train, max}} < t_{\text{test, min}}$.
2. **Horizon Buffer Separation:** A buffer gap of $H$ steps is placed between the end of train and the start of test sequences to prevent the train target horizon from overlapping with test features.
3. **Zero Random Shuffling:** Shuffling is prohibited during sequence generation; sequences maintain monotonic chronological ordering.