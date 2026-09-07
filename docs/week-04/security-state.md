# Day 25: Device Security State Specification

## 1. Status Taxonomy
- `NORMAL`: All telemetry conforms to nominal baseline; zero active alerts; risk score < 25.0.
- `MONITORED`: Minor baseline deviation or low-severity observation; heightened logging active.
- `SUSPICIOUS`: Port reconnaissance, abnormal connection attempts, or authentication failures detected.
- `AT_RISK`: Exposed critical vulnerability coupled with high neighbor threat likelihood.
- `COMPROMISED`: Confirmed exploitation, remote shell execution, or critical CIA degradation ($< 0.3$).
- `ISOLATED`: Quarantined node; physical/logical links severed in topology to prevent lateral spread.

## 2. State Evaluation Vector
Security State is quantified via:
$$\mathcal{SS} = \langle \text{Status}, \text{RiskScore}, \mathbf{CIA}, \text{Confidence}, \text{Alerts} \rangle$$