# Day 20: Anomaly Detection Feature Specifications

| Feature Name | Type | Sampling Window | Description | Threat Indicator |
|---|---|---|---|---|
| `packets_per_sec` (PPS) | Float | 1.0 Second | Rate of frame arrivals across interface | DoS/DDoS flood, high-speed automated scans |
| `bytes_per_sec` (BPS) | Float | 1.0 Second | Total throughput volume in bits/bytes | Data exfiltration, file transfer spikes |
| `unique_dst_ports` | Integer | 5.0 Seconds | Count of unique destination ports targeted | Vertical port scan reconnaissance |
| `unique_dst_ips` | Integer | 5.0 Seconds | Count of unique target IP addresses probed | Horizontal subnet sweeps, worm propagation |
| `syn_to_ack_ratio` | Float | 5.0 Seconds | Ratio of TCP SYN frames to ACK completions | SYN Flood attacks, half-open stealth scans |
| `payload_entropy` | Float | Per Packet | Shannon entropy score (0.0 to 8.0) | Encrypted C2 beaconing, tunneling on plain ports |