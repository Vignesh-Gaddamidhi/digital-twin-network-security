# Day 105: Complete Model Evaluation & Baseline Comparison

## 1. Metric Definitions in Cybersecurity Attack Detection
In network behavioral analysis, accuracy is often misleading due to class imbalance. The metrics are operationalized as follows:

| Metric | Mathematical Formula | SOC & Cyber Defense Meaning |
|---|---|---|
| **Accuracy** | $\frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$ | Global correctness across all benign flows and attack signatures. |
| **Precision** | $\frac{\text{TP}}{\text{TP} + \text{FP}}$ | **Alert Fidelity**: "When the model triggers an alert, how likely is it an actual cyber incident?" Low precision creates alert fatigue. |
| **Recall** | $\frac{\text{TP}}{\text{TP} + \text{FN}}$ | **Threat Detection Rate**: "Out of all ongoing attacks, what fraction did the detector catch?" Low recall leads to silent compromise. |
| **F1-Score** | $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ | Harmonic mean balancing detection completeness against operational alert fatigue. |
| **ROC-AUC** | $\int_0^1 \text{TPR}(\text{FPR}^{-1}(t)) dt$ | Threshold-independent discrimination power across varying operational risk profiles. |

## 2. False Positives vs. False Negatives
- **False Positive ($\text{FP}$, Normal $\to$ Anomalous):** Benign engineering traffic flagged as malicious. Triggers automated firewall blocks, throttling, and wasted SOC analyst triage hours.
- **False Negative ($\text{FN}$, Anomalous $\to$ Normal):** Undetected cyber breach. Data exfiltration or lateral movement goes unflagged, presenting severe organizational risk.
- **Model Selection Heuristic:** In production intrusion detection, a candidate model with slightly lower precision is preferable over one with lower recall, because missed attacks carry higher impact than false alerts.

## 3. Multi-Criteria Model Selection Score
Models are scored and ranked using a multi-factor operational rubric:
$$\text{Score} = 0.35 \cdot \text{Recall} + 0.30 \cdot \text{F1} + 0.15 \cdot \text{ROC-AUC} + 0.10 \cdot \text{Precision} + 0.10 \cdot \text{Accuracy} - \text{Penalty}_{\text{Latency}}$$