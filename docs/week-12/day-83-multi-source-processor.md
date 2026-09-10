# Day 83: Zeek -> Digital Twin & Multi-Source Event Processor

## 1. Architectural Independence
- The Digital Twin core is decoupled from engine specifics. It ingests solely `NormalizedSecurityEvent` models regardless of origin (`SURICATA`, `ZEEK`, or `SIMULATION`).
- The `MultiSourceEventProcessor` normalizes byte, packet, protocol, and application metadata into uniform entity properties.

## 2. 5-Tuple Temporal Correlation Engine
- Correlates independent telemetry streams sharing the same 5-tuple:
  `(sourceIP, destinationIP, sourcePort, destinationPort, protocol)`
  within a sliding temporal correlation window (`timeWindowSeconds = 10.0`).
- **Composite Security Context:** When Suricata generates an `ALERT` and Zeek simultaneously records an established `conn` flow for the same 5-tuple, they are linked into a single `SecurityCorrelationContext`.
- Correlated contexts link raw packet volume, protocol duration, and threat alert signatures to the affected target host in the Digital Twin.