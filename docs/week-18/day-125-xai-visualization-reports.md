# Day 125: XAI Visualizations, Forensic Reports & Audit Trail

## 1. Visual Presentation Architecture
To serve both autonomous agents and SOC human analysts, XAI outputs are formatted into distinct UI views:
1. **Prediction Explanation Card**: High-level summary tile displaying target identity, threat probability, category, confidence, and primary factor badges.
2. **Evidence Panel**: Quantitative telemetry values mapped into operational threat categories (`NORMAL`, `ELEVATED`, `HIGH`) based on baseline deviation.
3. **Why-This-Prediction Panel**: Visual indicator table showing directional influence ($\uparrow$ vs. $\downarrow$) and categorical contribution strength.
4. **Waterfall Attribution Chart**: Horizontal bar visualization showing the journey from baseline expectation $E[f(X)]$ to final probability $f(x)$.

## 2. Audit Trail & Cryptographic Reproducibility
Forensic accountability requires answering: *"Why did the system trigger this alert 30 days ago?"*
Every explanation generates an immutable cryptographic signature:
$$\text{inputHash} = \text{SHA256}\left(\text{SortedJSON}(\mathbf{x}_{\text{raw}}) \,\|\, \text{modelVersion} \,\|\, \text{featureVersion}\right)$$
This links the exact telemetry snapshot to the mathematical explanation.