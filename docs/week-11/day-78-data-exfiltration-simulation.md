# Day 78: SCN-EXFIL-001 (Synthetic Outbound Data Transfer Pattern)

## 1. Objective
Model sustained high-volume asymmetric egress data transfer from an internal asset (`CLIENT-01` or `DB-01`) to an external unclassified endpoint (`EXTERNAL-SIMULATED-ENDPOINT:443`) using synthetic byte sizes without real data collection.

## 2. Canonical Matrix Completion (7 / 7 Scenarios)
1. `SCN-PORTSCAN-001` (Port Scan) -> MEDIUM
2. `SCN-BRUTEFORCE-001` (Brute Force) -> HIGH
3. `SCN-DOS-001` (Traffic Saturation) -> HIGH
4. `SCN-DNS-001` (Suspicious DNS) -> MEDIUM
5. `SCN-BEACON-001` (C2 Beaconing) -> HIGH
6. `SCN-LATERAL-001` (Lateral Movement) -> HIGH
7. `SCN-EXFIL-001` (Data Exfiltration) -> CRITICAL

## 3. Expected Indicators
- `UNUSUAL_OUTBOUND_VOLUME`: Total egress payload bytes exceed 250,000 bytes.
- `UNUSUAL_DESTINATION`: Communication established with unclassified external asset.
- `HIGH_TRANSFER_RATE`: Egress transfer throughput exceeds 50,000 bytes/sec.
- `LONG_OUTBOUND_SESSION`: Active outbound data session duration exceeds 5.0s.