# Day 29: Network Device Model & Schema Specification

## 1. Domain Specification
The `NetworkDevice` model represents an individual physical or virtual computing node within the Network Digital Twin. 
Every device enforces:
- Immutable unique identifier (`id`).
- Fully qualified RFC 1123 hostname.
- Type-safe device classification (`DeviceTypeEnum`).
- Strict IPv4/IPv6 validation across multi-homed interfaces.
- Standard IEEE 802 MAC address formatting.
- Explicit network security zone assignment (`INTERNAL`, `DMZ`, `EXTERNAL`, `MANAGEMENT`).
- Decoupled operational current state and security FSM state.

## 2. Validation Constraints
| Field | Validation Constraint | Rejection Behavior |
|---|---|---|
| `id` | Non-empty alphanumeric string (`[a-zA-Z0-9_-]+`) | HTTP 422 / ValueError |
| `hostname` | Valid hostname, min 2 chars, alphanumeric & hyphens | HTTP 422 / ValueError |
| `type` | Must match one of `DeviceTypeEnum` members | HTTP 422 / ValueError |
| `ipAddresses` | Must be valid IPv4 / IPv6 network address | HTTP 422 / ValueError |
| `macAddresses`| Must match format `^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$` | HTTP 422 / ValueError |
| `networkZone` | Must match `NetworkZoneEnum` | HTTP 422 / ValueError |