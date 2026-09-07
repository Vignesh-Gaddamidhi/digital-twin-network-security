# Day 19: Security Event to MITRE ATT&CK Mapping Engine

## 1. Mapping Rules for the Digital Twin
| Observable Telemetry / Event | MITRE Tactic | Technique ID | Technique Name | Evidence Threshold |
|---|---|---|---|---|
| Inbound SYN sweeps to closed ports | Reconnaissance (`TA0043`) | `T1595.001` | Active Scanning: Port Scans | $\ge 3$ distinct ports probed within 5s |
| Multiple SSH/RDP auth rejections | Credential Access (`TA0006`) | `T1110.001` | Brute Force: Password Guessing | $\ge 5$ connection failures within 10s |
| Remote shell string (`/bin/sh`, cmd) | Execution (`TA0002`) | `T1059.004` | Command & Scripting Interpreter: Unix Shell | Direct payload string match |
| Internal workstation-to-server sweep | Discovery (`TA0007`) | `T1046` | Network Service Discovery | Private RFC 1918 subnet scanning |
| East-West SSH traffic from compromised node | Lateral Movement (`TA0008`) | `T1021.004` | Remote Services: SSH | Traffic originating from `COMPROMISED` host |
| High-volume outbound transfer to WAN | Exfiltration (`TA0010`) | `T1048` | Exfiltration Over Alternative Protocol | Egress volume exceeds rolling baseline 3x |