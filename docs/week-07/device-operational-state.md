# Day 44: Device Operational State & Transition Engine

## 1. State Matrix Decoupling
The Digital Twin maintains two orthogonal state dimensions per device:
- **Operational State:** Represents availability, responsiveness, and hardware/daemon runtime conditions.
- **Security State:** Represents confidentiality and integrity posture (compromise/exploit status).

## 2. Operational State Taxonomy
| State | Definition | Typical Trigger |
|---|---|---|
| `UNKNOWN` | Uninitialized or telemetry heartbeat lost | Initial boot or network partition |
| `STARTING` | Bootstrapping daemon/system processes | System startup sequence |
| `ACTIVE` | Normal operating parameters and healthy workload | CPU/Mem < 80%, responsive health checks |
| `DEGRADED` | Operating under impairment or resource exhaustion | High CPU (>90%), packet drop rate > 5% |
| `OFFLINE` | Powered off, crashed, or completely unreachable | Host failure, power loss, hypervisor crash |
| `MAINTENANCE` | Controlled administrative update mode | Scheduled patching, configuration push |
| `ISOLATED` | Disconnected from network fabric operationally | Emergency operational quarantine |

## 3. State Transition History Format
Every transition records the full audit vector:
```json
{
  "transitionId": "trans-e3a1b2c4",
  "deviceId": "web-01",
  "from": "ACTIVE",
  "to": "DEGRADED",
  "reason": "CPU reached 95% threshold under high load",
  "triggerSource": "TELEMETRY",
  "timestamp": "2026-09-08T08:05:00.000000Z"
}