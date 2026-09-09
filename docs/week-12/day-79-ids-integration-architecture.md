# Day 79: IDS Integration Architecture & Suricata Fundamentals

## 1. Architectural Principles
- **Decoupled Telemetry Ingestion:** The Digital Twin core does not depend on Suricata-specific or Zeek-specific schemas.
- **Normalization Boundary:** External JSON logs are parsed by specialized parsers and normalized by source adapters into a unified `NormalizedSecurityEvent`.
- **Topological IP-to-Twin Correlation:** Telemetry IP addresses (`src_ip`, `dest_ip`) are resolved against the `device_registry` to bind external security alerts to simulated graph nodes.

## 2. Generic Event Model Contract
- `eventId`: UUID identifier.
- `source`: `SURICATA` | `ZEEK` | `SIMULATION`.
- `eventType`: `ALERT` | `FLOW` | `DNS` | `HTTP` | `ANOMALY`.
- `sourceDevice` / `destinationDevice`: Digital Twin device IDs mapped from IPs.
- `sourceIP` / `destinationIP`: IPv4 / IPv6 addresses.
- `sourcePort` / `destinationPort`: TCP / UDP port numbers.
- `protocol`: Transport protocol string (`TCP`, `UDP`, `ICMP`).
- `severity`: Standardized `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`.
- `signature`: Signature or rule classification description.
- `category`: MITRE / Suricata alert category classification.
- `confidence`: Calibrated alert confidence score (0.0 to 1.0).
- `rawReference`: Original raw EVE / Zeek record for forensic auditing.