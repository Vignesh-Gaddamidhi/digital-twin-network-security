# Day 18: Security Information & Event Management (SIEM) Architecture

## 1. Core Capabilities
- **Log Aggregation:** Centralized ingestion of heterogeneous telemetry streams across firewalls, switches, web servers, and IDS engines.
- **Normalization:** Standardizing distinct vendor log structures into a unified semantic schema.
- **Correlation Engine:** Identifying temporal and causal linkages across distinct event types within specified time windows:
  $$\text{Incident} = \text{Event}_A(t) \wedge \text{Event}_B(t + \Delta t) \quad \text{where} \quad \Delta t \le \text{Threshold}$$
- **Threat Intelligence Matching:** Cross-referencing observable telemetry indicators against known malicious signatures and CVE registries.

## 2. Role in the Digital Twin
In our Digital Twin security platform:
- The SIEM layer maintains the centralized in-memory and persistent security event store.
- It normalizes incoming network packets and Suricata EVE logs into `SecurityEvent` objects.
- Correlated security alerts directly trigger state transitions on virtual nodes (`HEALTHY` -> `SUSPICIOUS` -> `COMPROMISED`).