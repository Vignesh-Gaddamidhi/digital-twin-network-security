# Day 17 Deliverable: Digital Twin Hybrid IDS/IPS Architecture

## 1. End-to-End Telemetry & Detection Pipeline

[ Virtual / Emulated Network Fabric ]
│
├─────────────────────────────────────────┐
▼ (Inline Path)                           ▼ (Passive Mirror)
[ Router/Firewall IPS ]                    [ Twin TAP / Sensor ]
│                                         │
(Enforces Drops)                                  ▼
│                                [ Suricata / Scapy Ingest ]
│                                         │
│                        ┌────────────────┴────────────────┐
│                        ▼                                 ▼
│             [ Signature Engine ]              [ Anomaly Detector ]
│             Matches Known Attack Strings       Evaluates PPS/Entropy Drift
│                        │                                 │
│                        └────────────────┬────────────────┘
│                                         ▼
│                              [ Normalized Alert Bus ]
│                                         │
▼                                         ▼
[ Automated Response Engine ] ◄────────────── [ Risk Calculation Engine ]
(Simulates Node Isolation)                             │
▼
[ Digital Twin Graph Sync ]
(Updates Device Security State)


## 2. Component Placement & Specifications
1. **Network Sensor Tap (`services/network_simulator/`):** Clones raw egress/ingress frames without injecting transit delay into the emulated environment.
2. **Signature Classifier Layer:** Executes deterministic pattern rules against packet payloads and header flags (detecting SYN scans, known exploit payloads, and unauthorized administrative ports).
3. **Statistical Anomaly Engine (`services/ml_pipeline/`):** Evaluates rolling time windows to measure:
   - Packet rate surges (PPS > baseline threshold).
   - Entropy anomalies (cleartext credentials vs. high-entropy encrypted blobs on non-standard ports).
   - Destination port diversity (identifying vertical and horizontal sweeps).
4. **Enforcement Bridge (Simulated IPS):** When an anomaly or signature exceeds the critical threshold, the engine injects a simulated firewall block rule or drops the active connection in the Digital Twin graph.