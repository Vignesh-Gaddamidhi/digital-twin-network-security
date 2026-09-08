# Day 56: Normal Traffic Orchestrator & Baseline Synthesis

## 1. Unified Protocol Blend
The orchestrator combines all seven lower and higher-layer generators into a realistic enterprise traffic profile:
- **DNS (30%):** Recursive name resolutions querying `*.internal.test` and `example.test` on UDP 53.
- **HTTPS (35%):** Encrypted TLS v1.3 web application browsing on TCP 443.
- **HTTP (15%):** Internal plaintext intranet and microservice REST calls on TCP 80.
- **SSH (8%):** Administrative sessions from `admin-01` to `server-01` on TCP 22.
- **ICMP (7%):** Diagnostic echo pings and health reachability probes.
- **Raw TCP/UDP (5%):** Underlying datagram flows and point-to-point socket transfers.

## 2. Digital Twin Feeding
Every generated event is mapped into the Digital Twin:
1. `network_state_engine`: Increments active session count and byte counters (`bytesSent`, `bytesReceived`).
2. `unified_state_coordinator`: Ingests calculated network utilization percentage (`networkUtilisation`).

## 3. Baseline Artifact (`normal-baseline-run-001`)
The baseline snapshot records exact empirical distributions used by Phase 7 Week 9 anomaly detectors:
- Total events generated
- Cumulative bytes transferred
- Protocol distribution percentages
- Port usage frequencies
- Destination IP/device breakdown