# Day 16: Risk Scoring Methodology & Mathematical Formulations

## 1. The Classical vs. Twin Risk Model
In classical static risk models:
$$\text{Risk} = \text{Likelihood} \times \text{Impact}$$

In our dynamic Digital Twin security platform, risk is parameterized continuously based on observable telemetry and active graph topological exposure:
$$\text{Composite Risk} = \left(\frac{C \times V}{10}\right) \times E \times P(\text{Threat}) \times (1.0 - M)$$

## 2. Dynamic Threshold Classifications
| Score Range | Severity Band | Twin Automated Action |
|---|---|---|
| `0.0 - 24.9` | **LOW** | Routine telemetry logging; standard polling intervals. |
| `25.0 - 49.9` | **MEDIUM** | Heightened DPI inspection; log retention prioritized. |
| `50.0 - 74.9` | **HIGH** | Rate-limiting incoming connections; trigger operator alert. |
| `75.0 - 100.0` | **CRITICAL** | Automated mitigation trigger: isolate node / drop port. |