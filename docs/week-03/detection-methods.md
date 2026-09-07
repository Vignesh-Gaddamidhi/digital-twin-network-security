# Day 17: Detection Methodologies & Heuristic Classifications

## 1. Modality Comparison Matrix
| Detection Method | Underlying Mechanism | Primary Strength | Operational Vulnerability |
|---|---|---|---|
| **Signature-Based** | Byte patterns, regex, static port matching | Deterministic; zero false positives on known CVEs | Blind to novel zero-days and encrypted variations |
| **Anomaly-Based** | Statistical drift against baseline distributions | Detects novel attack profiles and unknown techniques | High false-positive rate during business traffic shifts |
| **Behavioral** | Temporal sequence and state tracking over time | Tracks multi-step lateral movement and kill chains | Requires stateful memory and sliding window buffers |
| **Protocol Analysis**| RFC compliance and state machine validation | Flags out-of-spec framing and protocol tunneling | CPU intensive; requires deep application decoding |

## 2. Suricata Rule Schema Concepts
Suricata rules follow an explicit structure:
```text
action proto src_ip src_port -> dst_ip dst_port (msg:"..."; content:"..."; sid:100001; rev:1;)
alert tcp any any -> 192.168.1.10 any (msg:"SUSPICIOUS SHELL EXECUTION"; content:"/bin/sh"; sid:200001; rev:1;)