# Day 14: Unified NetworkEvent Schema Specification

## 1. Schema Definition
The `NetworkEvent` schema standardizes all network observations across physical wire taps, synthetic generation engines, and PCAP replays:

| Field | Type | Description |
|---|---|---|
| `event_id` | String (UUID4) | Unique event identifier |
| `timestamp` | String (ISO 8601 UTC) | Microsecond timestamp |
| `source_ip` | String | Source IPv4 address |
| `destination_ip` | String | Target IPv4 address |
| `source_mac` | String | Source Layer-2 hardware address |
| `destination_mac` | String | Destination Layer-2 hardware address |
| `source_port` | Optional[Integer] | Ephemeral or service source port |
| `destination_port`| Optional[Integer] | Destination service port |
| `protocol` | String | Transport protocol (`TCP`, `UDP`, `ICMP`, `OTHER`) |
| `detected_app` | String | L7 application protocol (`DNS`, `HTTP`, `TLS`, `UNKNOWN`) |
| `packet_size` | Integer | Wire length in bytes |
| `interface` | String | Originating interface identifier (`eth0`, `vlan1`) |
| `direction` | String | Flow orientation (`INBOUND`, `OUTBOUND`, `INTERNAL`) |
| `metadata` | Object | Low-level flags (e.g., TCP flags, entropy score) |