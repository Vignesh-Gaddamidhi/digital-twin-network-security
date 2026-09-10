# Day 84: Complete IDS Integration, Testing & Documentation

## 1. Unified Telemetry Ingestion Architecture
The Digital Twin operates as a dual-source platform capable of consuming both synthetic simulation events (Phase 7 & 8) and external IDS/NSM telemetry (Phase 9):

               NETWORK TRAFFIC (REAL / SYNTHETIC)
                               │
         ┌─────────────────────┴─────────────────────┐
         ▼                                           ▼
   SURICATA NIDS                                  ZEEK NSM
(Alerts, Signatures, EVE)                   (conn, dns, http, ssl, ssh)
         │                                           │
         ▼                                           ▼
  Suricata Adapter                              Zeek Adapter
         │                                           │
         └─────────────────────┬─────────────────────┘
                               ▼
                   [ NormalizedSecurityEvent ]
                               │
                               ▼
                  [ MultiSourceEventProcessor ]
                  ├── Event Deduplication (Idempotency)
                  ├── Out-of-Order Timestamp Preservation
                  ├── 5-Tuple Temporal Correlation
                  └── Topological Device Resolution
                               │
                               ▼
                       [ DIGITAL TWIN ]
             ┌─────────────────┴─────────────────┐
             ▼                                   ▼
    [ Network State Engine ]           [ Security State Engine ]
    - Active Sockets                   - Posture Transitions
    - Bandwidth & Throughput           - Alert History Ledgers

## 2. Core Resiliency Invariants
1. **Idempotent Ingestion:** Reprocessed events with identical IDs or matching `(source, timestamp, 5-tuple, signature)` hashes are deduplicated without re-mutating twin states.
2. **Timestamp Preservation:** Late-arriving or out-of-order network packets retain their true origin event timestamp while recording an ingestion arrival timestamp.
3. **Graceful Fault Degradation:** Malformed JSON, unmapped devices (`UNKNOWN_DEVICE`), unknown protocols, and missing timestamps are diverted to dead-letter queues without crashing the service.