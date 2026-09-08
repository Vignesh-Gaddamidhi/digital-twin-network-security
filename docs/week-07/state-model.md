# Phase 6: Unified Multi-Tier State Model
Every digital twin device encapsulates:
- **Identity:** Device ID, hostname, hardware profile.
- **Operational State:** `ACTIVE`, `DEGRADED`, `OFFLINE`, `MAINTENANCE`, `ISOLATED`.
- **Performance State:** `cpu`, `memory`, `networkUtilisation` (evaluated to `NORMAL`, `ELEVATED`, `HIGH`, `CRITICAL`).
- **Network State:** Active, closed, and failed Layer 4 session connections.
- **Port State:** Open, closed, and filtered socket listeners.
- **Service State:** Application daemon lifecycles (`RUNNING`, `STOPPED`, `DEGRADED`, `FAILED`).
- **Security & Vulnerability State:** Threat posture (`NORMAL` to `COMPROMISED`) and CVSS vulnerability exposure.