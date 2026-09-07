# Day 13: Rule-Based Anomaly Indicators

## 1. Indicator Hierarchy
- **`[INFO]`**: Normal operational traffic matching configured baseline policy (e.g., standard HTTP/HTTPS/DNS traffic to registered servers).
- **`[WARNING]`**: Policy drift or uncommon protocol usage (e.g., unexpected UDP ports, unclassified high-numbered ports, ICMP burst).
- **`[CRITICAL]`**: High-severity anomalies indicating active threats (e.g., sudden packet spikes $> 100 \text{ PPS}$, rapid failed connection attempts, connection attempts to unmapped internal addresses).

## 2. Difference Between Rule Indicators and ML
Rule-based indicators evaluate static conditional boundaries (`if packet_rate > threshold`). 
In Phase 3 and Phase 4, our ML Prediction Engine will evaluate multidimensional probability distributions across sliding temporal windows, catching subtle behavioral sequences that static rules miss.