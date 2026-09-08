# Day 57: Week 8 Integration & Normal Traffic Baseline

## 1. Canonical Topology Architecture
INTERNET
                        │
                        ▼
                   FIREWALL-01
                        │
                        ▼
                    ROUTER-01
                        │
                        ▼
                    SWITCH-01
          ┌─────────────┼──────────────┐
          │             │              │
          ▼             ▼              ▼
       WEB-01        DNS-01         CLIENT-01
          │
          ▼
        DB-01

## 2. Baseline Measurement Schema (`summary.json`)
- `totalPackets`: Sum of all Layer 4/7 packets generated.
- `totalBytes`: Total throughput volume across all interfaces.
- `trafficRateBps`: Average bytes per second.
- `protocolCounts`: Exact breakdown (`TCP`, `UDP`, `ICMP`, `HTTP`, `HTTPS`, `DNS`, `SSH`).
- `activeConnections`: Snapshot of active concurrent sessions.
- `averageConnectionsPerDevice`: Total active connections divided by host count.
- `portDistribution`: Packet distribution by destination port (22, 53, 80, 443, 5432, etc.).
- `protocolDistribution`: Percentage of overall traffic by protocol.

## 3. Dataset Artifacts
- `events.jsonl`: Normalized JSON Lines stream of all traffic transactions.
- `summary.json`: Empirical statistics for Week 9 anomaly detector baselining.
- `metadata.json`: Deterministic seed, duration, virtual clock ticks, and generation timestamp.