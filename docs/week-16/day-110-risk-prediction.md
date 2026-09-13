# Day 110: Contextual Risk Level Prediction Engine

## 1. Classical vs. ML Contextual Risk Formulation
In traditional security analysis:
$$\text{Risk} = \text{Likelihood} \times \text{Impact}$$

In our Digital Twin ML Risk Engine (`version: v2.0-ml-contextual`), this classical model is operationalized with continuous telemetry features and contextual asset properties:
- **Calibrated Likelihood ($L \in [0.0, 1.0]$):**
  $$L = P_{\text{threat}} \times \text{Confidence}_{\text{category}}$$
- **Operational Impact ($I \in [0.0, 1.0]$):**
  $$I = \text{Severity}_{\text{category}} \times \text{Criticality}_{\text{device}}$$
- **Contextual Environmental Multiplier ($M_{\text{env}} \in [1.0, 1.8]$):**
  $$M_{\text{env}} = 1.0 + (0.4 \times \text{Exposure}) + (0.4 \times \text{Vulnerability})$$

Composite Score:
$$\text{RiskScore} = \min\left(100.0, 100.0 \times (0.45 \cdot L + 0.55 \cdot I) \times M_{\text{env}}\right)$$

## 2. Qualitative Risk Level Boundaries (Configurable)
- **`LOW` ($0.0 \le \text{Score} < 30.0$):** Informational telemetry; routine automated watch.
- **`MEDIUM` ($30.0 \le \text{Score} < 60.0$):** Heightened interest; automated packet capture and flow rate rate-limiting.
- **`HIGH` ($60.0 \le \text{Score} < 85.0$):** Active security incident; automated ticket creation and SOC analyst alert.
- **`CRITICAL` ($85.0 \le \text{Score} \le 100.0$):** Imminent business impact; automated quarantine and host isolation.

## 3. Asset Contextual Multipliers
- **Device Criticality:**
  - `LOW`: $0.3$ (Isolated testing workstation)
  - `MEDIUM`: $0.6$ (Internal app server)
  - `HIGH`: $0.85$ (Domain controller, core gateway)
  - `MISSION_CRITICAL`: $1.0$ (Primary database, core payment gateway)
- **Network Exposure:**
  - `INTERNAL_ISOLATED`: $0.1$
  - `INTERNAL_ROUTABLE`: $0.4$
  - `DMZ`: $0.7$
  - `EXTERNAL_FACING`: $1.0$
- **Vulnerability Status:**
  - `NONE_KNOWN`: $0.0$
  - `PATCHED`: $0.2$
  - `MITIGATED`: $0.5$
  - `OPEN_UNPATCHED`: $1.0$