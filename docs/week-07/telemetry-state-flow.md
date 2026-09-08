# Phase 6: Real Network Telemetry Pipeline
REAL NETWORK -> Telemetry Collector -> Normalization -> StateEvent -> State Engine -> Twin State (Real)

- Ingests raw telemetry events from sensors, eBPF probes, and SNMP traps.
- Validates monotonicity, formats timestamps to UTC ISO-8601, and updates the `real` sub-state cache.