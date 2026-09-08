# Phase 5: Network Device Model
Represents computing nodes via `NetworkDeviceModel`.
- Enforces UUID/Alphanumeric ID, RFC 1123 hostname, `DeviceTypeEnum`, and `NetworkZoneEnum`.
- Validates multi-homed IPv4/IPv6 addresses and IEEE 802 MAC formatting.
- Decouples operational current health (`ONLINE`, `OFFLINE`, `DEGRADED`) from security posture (`NORMAL`, `SUSPICIOUS`, `COMPROMISED`).