# Day 25: State Transition Finite State Machine (FSM)

## 1. Degradation Logic (Attack Progression)
1. `NORMAL` $\to$ `MONITORED`: Triggered when feature $Z$-score $> 2.0$ or unmapped port is pinged.
2. `MONITORED` $\to$ `SUSPICIOUS`: Triggered when horizontal/vertical scans hit $\ge 3$ ports, or authentication fails repeatedly.
3. `SUSPICIOUS` $\to$ `COMPROMISED`: Triggered when an exploit signature (`T1059.004`, RCE) executes or CIA drops below $0.3$.
4. `COMPROMISED` $\to$ `ISOLATED`: Automated containment action executed by SOC/Twin policy.

## 2. Remediation Logic (Recovery Workflow)
1. `ISOLATED` $\to$ `REMEDIATED`: Rogue processes terminated; CVE patched; credentials revoked.
2. `REMEDIATED` $\to$ `MONITORED`: Host restored to network in quarantine VLAN for 300 seconds of telemetry observation.
3. `MONITORED` $\to$ `NORMAL`: Zero anomalies during observation period; nominal CIA scores confirmed.