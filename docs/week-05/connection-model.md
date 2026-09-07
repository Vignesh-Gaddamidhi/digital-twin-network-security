# Day 31: Network Connection Model & Schema Specification

## 1. Domain Overview
Connections bind devices into a coherent network topology graph.
A connection tracks:
- Source and destination device references (must resolve in the Device Registry).
- Optional source and destination interface names.
- Layer 4 transport protocol (`TCP`, `UDP`, `ICMP`, `ANY`).
- Port specifications (source ephemeral, destination listener).
- Structural connection type (`PHYSICAL`, `LOGICAL`, `NETWORK`, `SERVICE`).
- Operational link state (`ACTIVE`, `DEGRADED`, `BLOCKED`, `TERMINATED`).
- Telemetry metrics: bandwidth (Mbps) and latency (ms).

## 2. Relational Integrity Rules
| Constraint | Validation Check | Enforcement Action |
|---|---|---|
| Valid Endpoints | Source and destination IDs must exist in `device_registry` | HTTP 400 / DeviceNotFoundError |
| No Self-Loop | `sourceDevice != destinationDevice` | HTTP 400 / ValueError |
| Duplicate Rejection | No two active connections share the same ID or (src, dst, proto, dstPort) tuple | HTTP 409 / ConnectionAlreadyExistsError |
| Protocol Conformance | `protocol` must be `TCP`, `UDP`, `ICMP`, `ETHERNET`, or `ANY` | HTTP 422 / ValueError |
| Port Bounds | `sourcePort` and `destinationPort` must be within `1` to `65535` if specified | HTTP 422 / ValueError |