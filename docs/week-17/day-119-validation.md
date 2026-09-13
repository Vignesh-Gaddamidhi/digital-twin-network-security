# Day 119: Time-Series Evaluation, Digital Twin Integration & Phase 14 Milestone

## 1. Dual-Horizon Prediction Architecture
A major contribution of Phase 14 is the decoupling of current state from future trajectory:
- **Current Threat Probability ($P_{\text{curr}}$):** Evaluates instantaneous observation $X_t$ (e.g. $42\%$, within baseline tolerances).
- **Future Threat Probability ($P_{\text{fut}}$):** Evaluates sequential trend over window $X_{t-T+1:t}$ predicting likelihood of an attack emerging across future horizon $t+1 \dots t+H$ (e.g. $87\%$, escalating trajectory).

## 2. Early-Warning Timeliness Formulations
- **Operational Lead Time ($\Delta t_{\text{lead}}$):**
  $$\Delta t_{\text{lead}} = t_{\text{impact\_onset}} - t_{\text{first\_early\_warning}}$$
- **Early-Warning Success Rate:**
  $$\text{EWSR} = \frac{\sum \mathbb{I}(\Delta t_{\text{lead}} > 0 \land \text{Target} = \text{THREAT})}{\text{Total Attack Scenarios}}$$
- **False Early-Warning Rate:**
  $$\text{FEWR} = \frac{\sum \mathbb{I}(\text{Warning Issued} \land \text{No Attack Follows})}{\text{Total Benign Scenarios}}$$
- **Detection-Before-Impact Rate:**
  $$\text{DBIR} = \frac{\sum \mathbb{I}(t_{\text{warn}} \le t_{\text{escalation\_start}})}{\text{Total Attack Scenarios}}$$