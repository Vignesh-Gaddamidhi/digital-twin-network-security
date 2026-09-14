# Day 144: Live Network Traffic Monitoring & Telemetry Analytics

## 1. Metric Specifications
- **Packet Rate:** Packets per second across the active window ($\text{pkts/s}$).
- **Byte Velocity:** Data volume rate ($\text{KB/s}$ or $\text{MB/s}$).
- **Connection Ledger:** Active, Successful, and Failed handshakes with explicit Failure Rate ($\frac{\text{Failed}}{\text{Active} + \text{Failed}} \times 100\%$).
- **Protocol Distribution:** Percentage breakdown across application and transport protocols (`TCP`, `UDP`, `ICMP`, `HTTP`, `HTTPS`, `DNS`, `SSH`).

## 2. Dynamic Anomaly Detection Invariant
A traffic spike is declared when:
$$\text{CurrentRate} > \mu_{\text{baseline}} + (2.5 \times \sigma_{\text{baseline}})$$
Upon detection, the response correlates the telemetry frame with the active security scenario (`DOS_LIKE`, `PORT_SCAN`, `EXFILTRATION_LIKE`).