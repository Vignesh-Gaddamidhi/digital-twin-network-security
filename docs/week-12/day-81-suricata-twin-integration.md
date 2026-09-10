# Day 81: Suricata -> Digital Twin Integration

## 1. Architectural Scope
Connect normalized Suricata telemetry directly to the Digital Twin. Every external event updates state engines:
- Network telemetry (`flow`, `http`, `dns`, `tls`) updates active sessions, traffic volume, and last-seen timestamps.
- Security telemetry (`alert`) evaluates severity, drives state degradation (`NORMAL` -> `SUSPICIOUS` -> `COMPROMISED`), and records audit ledgers.

## 2. Dynamic Device Resolution Contract
- Resolution Hierarchy:
  1. `device_registry.getAllDevices()` matching `ipAddress` or secondary interface aliases.
  2. Subnet / Hostname heuristics for configured testing ranges.
  3. Unmapped / External IPs tagged as `UNKNOWN_DEVICE` with source IP and port captured.
- Zero-crash guarantee: Unregistered external or rogue addresses are routed to dynamic unknown device registries for asset discovery auditing.