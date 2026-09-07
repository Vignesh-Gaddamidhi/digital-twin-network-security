# Day 37: Topology Engine Specification

## 1. Responsibilities
The `TopologyEngine` is the authoritative coordinator for whole-network spatial analysis in the Digital Twin:
- **Device Lifecycle Sync:** Translates `NetworkDeviceModel` entries into active graph vertices.
- **Connection Lifecycle Sync:** Translates `NetworkConnectionModel` entries into directed/bidirectional edges.
- **Topological Inquiries:**
  - `findNeighbors(device_id)`: Resolves direct Layer 2/3 adjacencies.
  - `findPath(src_id, dst_id)`: Traverses minimum-hop or lowest-latency routes.
  - `detectIsolatedDevices()`: Discovers nodes with zero connectivity or severed links.
- **Topology Snapshot:** Produces structured metadata capturing active, inactive, and segmented network metrics.

## 2. Snapshot Format
```json
{
  "nodes": 8,
  "edges": 9,
  "zones": 4,
  "activeDevices": 7,
  "inactiveDevices": 1,
  "timestamp": "2026-09-07T19:15:00.000000Z"
}