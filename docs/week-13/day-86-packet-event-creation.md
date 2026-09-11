# Day 86: Packet -> Event Creation & Canonical NetworkEvent

## 1. Core Distinction: `source` vs `detectionSource`
- **`source`:** The network entity initiating traffic (e.g., `CLIENT-01` or `192.168.1.10`).
- **`destination`:** The network entity receiving traffic (e.g., `WEB-01` or `192.168.1.20`).
- **`detectionSource`:** The telemetry subsystem that captured or generated the observation (`SURICATA`, `ZEEK`, `SIMULATION`, or `PACKET_CAPTURE`).

## 2. Controlled EventType Vocabulary
- `NETWORK_CONNECTION`: General TCP/UDP connection session (e.g., Zeek `conn.log`).
- `DNS_QUERY`: Name resolution request/response (e.g., port 53, Zeek `dns.log`, Suricata `dns`).
- `HTTP_REQUEST`: Cleartext web request (port 80/8080, `http.log`).
- `HTTPS_CONNECTION`: Encrypted TLS/HTTPS session (port 443, `ssl.log`).
- `SSH_CONNECTION`: Secure shell administrative session (port 22, `ssh.log`).
- `AUTHENTICATION_EVENT`: Authentication attempt/outcome.
- `PORT_ACTIVITY`: Scanning, probes, or unmapped port handshakes.
- `TRAFFIC_SPIKE`: Volumetric saturation anomaly.
- `PROTOCOL_ANOMALY`: Non-standard behavior or RFC violation.
- `IDS_ALERT`: Signature rule match with security threat implication.

## 3. Severity Semantics
- Informational or benign connection observations default to `INFO` or `None` rather than fabricating an artificial threat level.
- True threat indicators carry calibrated values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.