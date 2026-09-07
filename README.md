# Digital Twin-Based Network Security Simulation & Attack Prediction Platform

## Project Overview
An end-to-end security modeling platform combining network programming, synthetic traffic generation, PCAP forensics, real-time IDS/IPS telemetry, SIEM event correlation, and predictive state graph modeling.

---

## Phase Progress Roadmap

### ✅ Phase 1: Network Fundamentals (Week 1 — Days 1 to 7)
- OSI 7-Layer & TCP/IP models, IP addressing, Subnetting, Ethernet framing.
- Protocols: ARP, DHCP, DNS, TCP, UDP, HTTP, HTTPS, Routing, NAT, Firewalls.
- Canonical Network Inventory (Devices D001 through D005).

### ✅ Phase 2: Network Programming & Traffic Pipeline (Week 2 — Days 8 to 14)
- Python Sockets: TCP client/server state machines; UDP datagram transmission.
- Scapy Crafting: Layer composition (`Ether / IP / TCP / Payload`), field manipulation, Shannon entropy.
- Telemetry & PCAP: Binary PCAP parsing, protocol classifier (`DNS`, `HTTP`, `TLS`), JSON serialization.
- Generators & Monitored Flows: Behavioral profiles (`WEB_BROWSING`, `DNS_HEARTBEAT`, `ICMP_PING`), PPS/BPS rate meters.
- Closed-loop pipeline from traffic synthesis to Digital Twin API ingest.

### ✅ Phase 3: Cybersecurity Fundamentals & Anomaly Detection (Week 3 — Days 15 to 21)
- Security Governance: Dynamic CIA Triad degradation modeling on virtual nodes.
- Risk Modeling: Dynamic composite risk equations, attack surface analysis, CVSS scoring.
- Detection Systems: Hybrid IDS/IPS engine (signature rules + statistical thresholds), Suricata EVE logs.
- Centralized SIEM & SOC: Log lifecycle, multi-event sliding window correlation, automated incident triggers.
- MITRE ATT&CK: Kill-chain taxonomy mapping (`TA0043`, `TA0002`, `TA0006`, `TA0008`) with confidence scores.
- Anomaly Detector: Standalone `network_anomaly_detector` service with standard-score ($Z$-score) continuous scoring $[0, 100]$.

### ✅ Phase 4: Digital Twin Fundamentals & Core Assembly (Week 4 — Days 22 to 28)
- Concept Formulation: Formal definition $\mathcal{DT}(t) = \langle \mathcal{G}, \mathcal{S}, \mathcal{V}, \mathcal{R}, \Phi \rangle$, 9-stage lifecycle.
- Device Digital Twin: Multi-homed interface modeling, OS kernel profiles, port registries, service daemons.
- Network Topology: Directed multigraph modeling in NetworkX, Dijkstra shortest path, articulation points.
- Dual-Track State Model: Decoupled Current Operational State (`ONLINE`, `DEGRADED`) from Security State (`NORMAL`, `SUSPICIOUS`, `COMPROMISED`, `ISOLATED`) with an immutable transition audit trail.
- Attack Surface & Vulnerabilities: Environmental exposure tiers (`INTERNAL`, `DMZ`, `EXTERNAL`), vulnerability lifecycles (`OPEN`, `MITIGATED`, `PATCHED`).
- Core Engine Assembly: Built `services/digital_twin/core/` with Device, Connection, Topology, State, and Vulnerability engines.
- Closed-Loop Synchronization: Connected the Week 3 Network Anomaly Detector to the Digital Twin Core, verifying real-time FSM escalation and failure rejection.

---

## Upcoming Phases
- **Phase 5: Network Digital Twin Engine & Scalability (Weeks 5 to 7)**
- **Phase 6: Simulation & Attack Scenarios (Weeks 8 to 11)**
- **Phase 7: Machine Learning & Attack Prediction (Weeks 12 to 18)**