# Day 24: Connection Object & Relationship Specification

## 1. Connection Taxonomy
In the Network Security Digital Twin, connections are categorized into three operational tiers:
1. **`PHYSICAL_LINK`**: Direct Layer 1/2 media links. Characteristics include maximum bandwidth capacity (Mbps), physical interface names, and cable medium.
2. **`LOGICAL_ROUTED`**: Layer 3 IP routing relationships. Defines next-hop routes, gateway traversal, and subnet boundary crossings.
3. **`SERVICE_SESSION`**: Ephemeral Layer 4/7 transport flows. Tracks active 5-tuple state (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`), byte volume, and session state (`ESTABLISHED`, `TIME_WAIT`).

## 2. Canonical Connection Schema
| Field | Type | Description |
|---|---|---|
| `connection_id` | String (UUID) | Unique connection identifier |
| `source_device_id` | String | Originating node ID |
| `destination_device_id` | String | Terminating node ID |
| `connection_type` | String | `PHYSICAL_LINK`, `LOGICAL_ROUTED`, or `SERVICE_SESSION` |
| `protocol` | String | Transport or physical framing (`ETHERNET`, `TCP`, `UDP`) |
| `source_port` | Optional[Integer] | Ephemeral or service source port |
| `destination_port` | Optional[Integer] | Target service port |
| `status` | String | `ACTIVE`, `DEGRADED`, `BLOCKED` |
| `latency_ms` | Float | Link propagation delay |
| `bandwidth_mbps` | Float | Maximum line rate |