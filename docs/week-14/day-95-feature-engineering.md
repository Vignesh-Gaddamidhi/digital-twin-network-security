# Day 95: ML Feature Engineering Engine & Feature Registry

## 1. Required Feature Definitions (9 Categories)

| # | Feature Name | Field Name(s) | Type | Unit | Formula / Calculation | Missing-Value Policy | Range |
|---|---|---|---|---|---|---|---|
| 1 | Packet Rate | `packet_rate` | `float` | pkts/s | $\frac{\text{packets}}{\max(\text{windowSeconds}, 0.001)}$ | Impute from $1/\text{duration}$ | $[0.0, \infty)$ |
| 2 | Bytes | `bytes`, `bytes_per_second` | `int`, `float` | bytes, B/s | Cumulative payload volume; $\frac{\text{bytes}}{\text{windowSeconds}}$ | Default to $0$ | $[0, \infty)$ |
| 3 | Connection Frequency | `connection_frequency` | `float` | conns/s | $\frac{\text{connections}}{\max(\text{windowSeconds}, 0.001)}$ | Default to $1.0$ | $[0.0, \infty)$ |
| 4 | Port Distribution | `port_22_ratio`, `port_53_ratio`, `port_80_ratio`, `port_443_ratio`, `port_other_ratio`, `unique_destination_ports` | `float` (ratios), `int` | ratio, count | $\frac{N_{\text{port}}}{N_{\text{total}}}$; $|\text{unique ports}|$ | Ratio $0.0$ if no traffic to port; port $0$ counted as `other` | Ratios $[0.0, 1.0]$, count $[1, 65536]$ |
| 5 | Flow Duration | `flow_duration` | `float` | seconds | $t_{\text{end}} - t_{\text{start}}$ | Minimum instantaneous floor $0.001\,\text{s}$ | $[0.001, \infty)$ |
| 6 | Protocol Distribution | `tcp_ratio`, `udp_ratio`, `icmp_ratio` | `float` | ratio | $\frac{N_{\text{proto}}}{N_{\text{total}}}$ | Unobserved protocols default to $0.0$; sum equals $1.0$ | $[0.0, 1.0]$ |
| 7 | Failed Connections | `failed_connections`, `failed_connection_rate` | `int`, `float` | count, ratio | Count of `REJ`/`S0`/failures; $\frac{\text{failed}}{\max(1, \text{total})}$ | Default to $0$ count and $0.0$ ratio | Count $[0, \infty)$, ratio $[0.0, 1.0]$ |
| 8 | DNS Frequency | `dns_queries`, `dns_frequency` | `int`, `float` | count, q/s | Cumulative DNS lookups; $\frac{\text{dns\_queries}}{\text{windowSeconds}}$ | Default to $0$ and $0.0$ if non-DNS | $[0.0, \infty)$ |
| 9 | Destination Diversity | `destination_diversity`, `unique_destination_ratio` | `int`, `float` | count, ratio | $|\text{unique destinations}|$; $\frac{|\text{unique destinations}|}{N_{\text{connections}}}$ | Default to $1$ count and $1.0$ ratio | Count $[1, \infty)$, ratio $[0.0, 1.0]$ |

## 2. Flat Tabular Representation
Every categorical distribution is explicitly unpacked into bounded float ratio columns (`tcp_ratio`, `udp_ratio`, `icmp_ratio`, `port_22_ratio`, `port_53_ratio`, `port_80_ratio`, `port_443_ratio`, `port_other_ratio`). This provides a fixed-width vector ready for Scikit-Learn, PyTorch, or XGBoost without one-hot encoding instability.