# Day 43: Digital Twin State Engine Architecture

## 1. Modular State Taxonomy
Device state is decomposed into distinct, strongly-typed domains:
- **Operational State:** High-level operational mode (`ACTIVE`, `DEGRADED`, `OFFLINE`, `MAINTENANCE`).
- **Performance State:** Continuous telemetry metrics:
  - `cpu`: CPU utilization percentage ($0.0 \le x \le 100.0$).
  - `memory`: RAM utilization percentage ($0.0 \le x \le 100.0$).
  - `networkUtilisation`: Interface saturation percentage ($0.0 \le x \le 100.0$).
- **Network State:** Dynamic link session counts (`activeConnections`).
- **Port State:** Open Layer 4 listening ports with service bindings.
- **Service State:** Application daemon runtimes (`RUNNING`, `DEGRADED`, `STOPPED`).
- **Security State:** Threat status (`NORMAL`, `SUSPICIOUS`, `COMPROMISED`) and vulnerability exposure counts (`OPEN`, `MITIGATED`).

## 2. Invariant Validation Rules
| Sub-State | Constraint | Validation Rule | Error Thrown |
|---|---|---|---|
| Performance | CPU Range | $0.0 \le \text{cpu} \le 100.0$ | `ValueError: CPU utilization must be between 0.0 and 100.0%` |
| Performance | Memory Range | $0.0 \le \text{memory} \le 100.0$ | `ValueError: Memory utilization must be between 0.0 and 100.0%` |
| Performance | Network Saturation | $0.0 \le \text{network} \le 100.0$ | `ValueError: Network utilization must be between 0.0 and 100.0%` |
| Device | Identity Check | Target must exist in `device_registry` | `DeviceNotFoundError` |
| History | Immutability | Prior records cannot be overwritten | Append-only ledger |