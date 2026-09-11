# Day 87: Event Normalization & Alignment

## 1. Normalization Invariants
- **Dual Timestamps:**
  - `eventTimestamp`: Preserves original sensor/packet occurrence time in normalized ISO-8601 UTC format (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`). Supports Unix epoch seconds/microseconds, ISO strings with offsets, and RFC 3339 formats.
  - `processingTimestamp`: The UTC timestamp when the event entered the pipeline.
- **Topological Entity Resolution:** Raw IP addresses (`192.168.1.10`), device identifiers (`CLIENT-01`), and hostname aliases are resolved to Digital Twin inventory IDs. Unresolvable addresses are quarantined or marked `UNKNOWN_DEVICE`.
- **Protocol Case-Insensitive Harmonization:** Variations (`tcp`, `Tcp`, `TCP`, `6`) coerce strictly to uppercase canonical strings (`TCP`, `UDP`, `ICMP`).
- **Port Numerical Coercion:** Stringified port numbers (`"443"`), floating representations (`443.0`), or raw integer ports strictly cast to integer range `0 <= port <= 65535`.
- **Detection Source Taxonomy:** Strictly controlled: `SURICATA`, `ZEEK`, `SIMULATION`, `ANOMALY_DETECTOR`.

## 2. Quarantine & Rejection Policy
Inputs with missing endpoints, unparseable timestamps, out-of-bounds ports, or unsupported transport protocols are rejected with diagnostic error reasons and recorded in the quarantine registry.