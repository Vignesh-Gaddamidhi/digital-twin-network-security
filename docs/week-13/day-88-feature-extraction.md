# Day 88: Feature Extraction Layer & Sliding Window Aggregation

## 1. Dimensional Feature Taxonomy
Features are extracted across six quantitative dimensions:
1. **Volume:** `packetCount`, `byteCount`, `packetRate` (pkts/sec), `byteRate` (bytes/sec).
2. **Connection:** `connectionCount`, `failedConnectionCount`, `successfulConnectionCount`, `connectionRate`, `failedConnectionRatio`, `averageConnectionDuration`.
3. **Port:** `destinationPort`, `uniqueDestinationPorts`, `portAttemptCount`, `failedPortAttempts`.
4. **Protocol:** `protocol`, `protocolCount`, `protocolRatioTCP`, `protocolRatioUDP`, `uniqueProtocols`.
5. **Timing:** `eventFrequency`, `interArrivalTime`, `averageInterval`, `intervalVariance` (critical for detecting low-jitter C2 beaconing).
6. **Direction:** `inboundBytes`, `outboundBytes`, `inboundPackets`, `outboundPackets`, `bytesDirectionRatio`.

## 2. Sliding Window Aggregation
- **5-Second Window (`WINDOW_5S`):** Rapid burst, SYN flood, and volumetric saturation detection.
- **30-Second Window (`WINDOW_30S`):** Port sweep scans, brute-force failure cascades.
- **60-Second Window (`WINDOW_60S`):** Periodic command-and-control beaconing, low-and-slow exfiltration.