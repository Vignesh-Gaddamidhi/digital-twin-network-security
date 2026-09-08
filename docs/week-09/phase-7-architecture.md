# Phase 7: Network Simulation Engine — Complete Architecture

## 1. Tripartite System Boundary
             NETWORK DIGITAL TWIN
                     │
         ┌───────────┴───────────┐
         │                       │
    REAL NETWORK            SIMULATION
         │                       │
    Real telemetry         Synthetic events
         │                       │
         └───────────┬───────────┘
                     ▼
                TWIN STATE
                     │
                     ▼
             ANOMALY DETECTOR
                     │
                     ▼
              SECURITY EVENT

## 2. Separation of Physical Telemetry and Security Interpretation
The simulation engine never directly classifies traffic as an "attack":
- The engine generates quantifiable physical telemetry: packet bursts, connection arrival skews, non-listening port sweeps, and protocol distribution drift.
- The Digital Twin reflects these physical strains on host resources (CPU, Memory, Network Utilisation, Open Ports, Socket Tables).
- Downstream statistical detectors evaluate deviation from Week 8 baselines to declare Security Events.

## 3. Supported Scenarios
- **Normal Protocols:** HTTP (80), HTTPS (443), DNS (53), SSH (22), ICMP, raw TCP, raw UDP.
- **Abnormal Categories:**
  1. `TRAFFIC_SPIKE`: Volumetric surges (e.g. 100 -> 800 events/min).
  2. `CONNECTION_ANOMALY`: Rapid session creation with lifecycle skews (High `NEW`, Low `ESTABLISHED`, High `FAILED`).
  3. `PORT_ANOMALY`: Broad destination port sweeps with dynamic attack surface mutation (`8080 -> OPEN`).
  4. `PROTOCOL_ANOMALY`: Distribution skewing (e.g. ICMP surging to 65% of overall traffic).
  5. `REPEATED_CONNECTION`: Looped connection flaps (100 attempts in 10s: 3 successes, 97 failures).