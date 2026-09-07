# Day 25: Operational Current State Specification

## 1. Domain Overview
Operational Current State represents the physical and hardware health of a device node.
A device can be completely operational while concurrently suffering a severe security compromise.

## 2. Core Metrics
- `status`: `ONLINE`, `DEGRADED`, `OFFLINE`, `MAINTENANCE`, `UNKNOWN`
- `uptime_seconds`: Continuous system execution time.
- `cpu_usage_pct`: Host processor consumption (0.0 to 100.0).
- `memory_usage_pct`: Resident memory allocation (0.0 to 100.0).
- `network_state`:
  - `packet_rate_pps`: Real-time ingress/egress frames per second.
  - `byte_rate_bps`: Real-time bits per second.
  - `active_connections_count`: Open socket sessions tracked in kernel.
  - `latency_ms`: Round-trip hop latency.