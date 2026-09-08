# Day 62: Protocol Anomaly & Distribution Skew Simulation

## 1. Distribution Modeling
Tracks proportional shift across three distinct operational periods:
1. **Normal Profile:** Typical enterprise baseline:
   - HTTPS: 60%
   - DNS: 20%
   - HTTP: 10%
   - SSH: 5%
   - ICMP: 5%
2. **Abnormal Profile:** Skewed protocol composition:
   - ICMP: 65%
   - HTTPS: 20%
   - DNS: 5%
   - HTTP: 5%
   - SSH: 5%
3. **Recovery Profile:** Returns to normal distribution baseline.

## 2. Event Contract
```json
{
  "eventId": "proto-anom-001",
  "anomalyType": "PROTOCOL_ANOMALY",
  "timeWindow": "WINDOW_2_ABNORMAL",
  "expectedProtocol": "HTTPS",
  "observedProtocol": "ICMP",
  "expectedPercentage": 5.0,
  "observedPercentage": 65.0,
  "deviation": 0.60,
  "timestamp": "2026-09-08T18:30:00.000000Z"
}
Scientific Principle
An observed statistical abnormality does not automatically equal a confirmed cyberattack:

A sudden surge in ICMP could be automated diagnostic scripts, MTU discovery sweeps, or router keep-alives.

The simulator logs physical observable distributions; anomaly detectors determine whether to raise an alert.