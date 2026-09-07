# Day 12: Network Traffic Generator Architecture

## 1. Packet Generator vs. Traffic Generator
- **Packet Generator:** Stateless builder creating isolated protocol frames on demand.
- **Traffic Generator:** Stateful behavioral engine creating realistic sequences of frames with simulated delays, jitter, stateful handshakes, and application payloads.

## 2. Closed-Loop Telemetry Pipeline
[ Traffic Generator ] ──► [ PCAP Stream ] ──► [ Day 11 Parser ] ──► [ Normalized JSON ] ──► [ Digital Twin Graph ]

This closed loop ensures synthetic simulation data matches the exact JSON schema required by downstream intrusion detection and machine learning prediction engines.