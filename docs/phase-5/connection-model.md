# Phase 5: Network Connection Model
Encapsulates relationships between devices via `NetworkConnectionModel`:
- Categorized as `PHYSICAL`, `LOGICAL`, `NETWORK`, or `SERVICE`.
- Rejection of self-loops (`source != destination`) and duplicate active links.
- Tracks metrics: line rate bandwidth (Mbps), propagation latency (ms), and status (`ACTIVE`, `DEGRADED`, `BLOCKED`, `TERMINATED`).