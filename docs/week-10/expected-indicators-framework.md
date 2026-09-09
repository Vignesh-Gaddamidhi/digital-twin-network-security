# Day 68: Expected Indicators Framework

## 1. Concept
An indicator is a quantifiable signature that an anomaly detector or SIEM correlation engine is expected to flag when a specific attack pattern is simulated.

## 2. Nine Canonical Indicator Types
1. `HIGH_CONNECTION_RATE`: Connection creation frequency exceeds baseline.
2. `HIGH_FAILED_CONNECTION_RATE`: Ratio or count of failed/reset connections spikes.
3. `UNUSUAL_PORT_ACTIVITY`: Access attempts across unallocated or wide port spreads.
4. `UNUSUAL_PROTOCOL_DISTRIBUTION`: Protocol shares skew away from normal distribution.
5. `PERIODIC_TRAFFIC`: Low interval variance indicating automated C2 beaconing.
6. `TRAFFIC_VOLUME_SPIKE`: Sudden surge in byte throughput saturating interfaces.
7. `UNUSUAL_DESTINATION`: Contacts directed toward non-standard external/internal IPs.
8. `UNUSUAL_DNS_FREQUENCY`: High frequency of DNS lookups or subdomain probing.
9. `UNUSUAL_OUTBOUND_VOLUME`: Sustained egress payload transfer indicative of exfiltration.

## 3. Evaluation Schema
- `direction`: `GREATER_THAN`, `LESS_THAN`, `EQUALS`, `DEVIATION_EXCEEDS`
- `threshold`: Numeric trigger level
- `confidence`: Confidence score (0.0 to 1.0)