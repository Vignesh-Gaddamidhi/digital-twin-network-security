# Day 13: Connection State Tracking

## 1. Connection Tuple Abstraction
Sessions are tracked using the canonical 5-tuple:
`Session Key = (Source IP, Destination IP, Protocol, Destination Port)`

## 2. Dynamic Connection Table Schema
| Field | Type | Description |
|---|---|---|
| `source_ip` | String | Initiating endpoint IP |
| `destination_ip` | String | Target service IP |
| `protocol` | String | Transport Protocol (TCP, UDP, ICMP) |
| `port` | Integer | Destination Service Port |
| `state` | String | ACTIVE, CLOSED, HALF_OPEN |
| `packet_count` | Integer | Cumulative packets in this connection |
| `byte_count` | Integer | Cumulative bytes transferred |
| `last_seen` | Timestamp | Microsecond timestamp of latest packet |