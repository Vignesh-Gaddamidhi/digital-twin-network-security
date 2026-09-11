# Day 89: Detection Engine & Explainable Behavioral Analysis

## 1. Architectural Principles
- **Explainable Evidence:** Detections must provide auditable evidence blocks capturing the observed metric, baseline expected value, observed value, and deviation score.
- **Hypothesis Over Absolute Certainty:** The engine flags `Potential suspicious behaviour detected` rather than asserting a definitive intrusion.
- **Calibrated Confidence:** Confidence scores ($0.0 \le C \le 1.0$) are computed through bounded scoring functions based on Z-score standard deviations and ratio margins.

## 2. Detection Types
- `TRAFFIC_SPIKE`: Significant deviation in `packetRate` or `byteRate` exceeding baseline standard deviations ($Z \ge 3.0$).
- `CONNECTION_ANOMALY`: Rapid surge in concurrent sessions or `failedConnectionRatio` exceeding threshold.
- `PORT_ANOMALY`: Rapid expansion in `uniqueDestinationPorts` indicating reconnaissance or port scanning.
- `PROTOCOL_ANOMALY`: Non-standard transport usage or protocol mix disruption.
- `REPEATED_CONNECTION`: Rapid repeated handshakes toward a single destination.
- `DNS_ANOMALY`: High-frequency DNS queries or anomalous record clustering.
- `BEACONING_PATTERN`: Periodic recurring heartbeats characterized by low `intervalVariance` ($\le 0.05\,\text{s}^2$).
- `AUTHENTICATION_ANOMALY`: Elevated failure frequency and repeated authentication failures.
- `OUTBOUND_VOLUME_ANOMALY`: Asymmetric data transfer where `outboundBytes` and `bytesDirectionRatio` surge.