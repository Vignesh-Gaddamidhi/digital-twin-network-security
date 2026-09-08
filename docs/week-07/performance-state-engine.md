# Day 45: CPU & Memory Performance State Engine

## 1. Metric Threshold Formulation
Telemetry feeds continuous CPU and RAM usage percentages. These values are mapped to qualitative tiers:

| Range (%) | Classification | Operational Meaning |
|---|---|---|
| `0.0% - <60.0%` | `NORMAL` | Baseline operating parameters |
| `60.0% - <80.0%` | `ELEVATED` | Increased load, non-concerning spike |
| `80.0% - <95.0%` | `HIGH` | Resource contention; operational degradation alert |
| `95.0% - 100.0%` | `CRITICAL` | Severe resource exhaustion; imminent service failure |

## 2. Invariant Bounds
Strict validation guarantees numeric values remain within physical limits:
- $0.0 \le \text{CPU} \le 100.0$ (Values $< 0.0$ or $> 100.0$ throw `ValueError`)
- $0.0 \le \text{Memory} \le 100.0$ (Values $< 0.0$ or $> 100.0$ throw `ValueError`)

## 3. Historical Telemetry Audit Record
```json
{
  "recordId": "perf-a1b2c3d4",
  "deviceId": "web-01",
  "cpu": 92.0,
  "cpuLevel": "HIGH",
  "memory": 89.0,
  "memoryLevel": "HIGH",
  "performanceState": "HIGH",
  "source": "TELEMETRY",
  "timestamp": "2026-09-08T10:15:00.000000Z"
}