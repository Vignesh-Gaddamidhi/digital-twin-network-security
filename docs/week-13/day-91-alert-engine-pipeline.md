# Day 91: Security Alert Engine & Complete Pipeline Integration

## 1. Canonical SecurityAlert Model
Every generated alert preserves the 8 mandatory core security attributes:
1. `timestamp`: Origin event timestamp (ISO-8601 UTC).
2. `source`: Initiating host/IP (`CLIENT-01`).
3. `destination`: Target host/IP (`WEB-01`).
4. `protocol`: Transport protocol (`TCP`, `UDP`, `ICMP`).
5. `port`: Destination port integer.
6. `eventType`: Semantic classification (`PORT_ACTIVITY`, `TRAFFIC_SPIKE`, `IDS_ALERT`, etc.).
7. `severity`: Evaluated severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
8. `detectionSource`: Telemetry origin (`SURICATA`, `ZEEK`, `SIMULATION`, `PACKET_CAPTURE`).

Along with contextual lifecycle metadata:
- `alertId`: Unique identifier (`ALT-XXXXXX`).
- `detectionType`: Algorithmic category (`PORT_ANOMALY`, `BEACONING_PATTERN`, etc.).
- `confidence`: Calibrated detection confidence (0.0 to 1.0).
- `riskScore`: Contextual risk score (0.0 to 100.0).
- `riskLevel`: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`.
- `evidence`: Structured explainability list.
- `affectedDevice`: Target twin host (`WEB-01`).
- `status`: `NEW` | `ACKNOWLEDGED` | `INVESTIGATING` | `RESOLVED` | `FALSE_POSITIVE` | `CLOSED`.
- `createdAt`: Alert generation timestamp.

## 2. Pipeline State Transitions & Digital Twin Guardrails
Devices do not jump automatically to `COMPROMISED` simply because an alert exists. Instead, alerts drive state transitions through controlled thresholds:
- `NORMAL` -> `SUSPICIOUS` -> `UNDER_ATTACK` -> `COMPROMISED` (or `RECOVERING`).
- High-severity or critical alerts transition target devices to `SUSPICIOUS` or `UNDER_ATTACK`, with `COMPROMISED` reserved for confirmed exploits or verified data exfiltration.

## 3. Observability & Stage Duration Tracking
For every event processed through the pipeline, stage-level millisecond latency metrics and error codes are captured:
- `ingestionDuration`
- `normalizationDuration`
- `featureExtractionDuration`
- `detectionDuration`
- `riskDuration`
- `alertDuration`