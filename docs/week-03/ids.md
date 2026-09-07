# Day 17: Intrusion Detection Systems (IDS) Fundamentals

## 1. Operating Mechanics
- **Deployment:** Deployed out-of-band via physical TAPs, virtual switch port mirroring (SPAN), or eBPF kernel packet probes.
- **Core Function:** Monitors and inspects ingress/egress frame flows passively without altering packets or delaying line-rate transmission.
- **Output:** Emits structured security audit logs and security telemetry records (e.g., Suricata EVE JSON format).

## 2. Classification
- **NIDS (Network IDS):** Analyzes multi-host segment traffic passing over virtual and physical switches.
- **HIDS (Host IDS):** Runs as an operating system agent monitoring local system call tables, authentication logs, and file integrity (e.g., OSSEC, Wazuh).