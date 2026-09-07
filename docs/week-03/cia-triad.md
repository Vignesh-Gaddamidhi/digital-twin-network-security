# Day 15: The CIA Triad in Network Security & Digital Twin Modeling

## 1. Pillars of Information Security
- **Confidentiality:** Data and asset state must remain shielded from unauthorized visibility.
  - *Network Protections:* TLS 1.3 encryption, VLAN boundary isolation, encrypted packet payloads.
  - *Twin Metrics:* Detection of data egress to untrusted WAN IPs; payload entropy shifts indicating cleartext credential leakage.
- **Integrity:** Ensuring information and configurations cannot be modified maliciously or accidentally without detection.
  - *Network Protections:* Cryptographic checksums (TCP/IP checksums verify transmission integrity; HMAC/TLS verifies cryptographic integrity), ARP table lockouts.
  - *Twin Metrics:* Unauthorized MAC changes for known IP addresses (ARP cache poisoning), configuration drift alerts.
- **Availability:** Systems, paths, and services must remain responsive to legitimate operational traffic.
  - *Network Protections:* Link aggregation, SYN flood protection cookies, egress rate limiters.
  - *Twin Metrics:* CPU/connection pool saturation, latency spike alerts, node state transitioning from `ONLINE` to `DEGRADED` or `UNREACHABLE`.

## 2. Quantitative CIA Degradation Index
In the Digital Twin engine, each asset maintains a CIA score vector $(C, I, A)$ bounded between $0.0$ (Compromised) and $1.0$ (Nominal):
$$\text{Asset Health} = \min(C, I, A)$$