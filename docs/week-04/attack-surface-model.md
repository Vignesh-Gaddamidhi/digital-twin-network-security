# Day 26: Digital Attack Surface & Exposure Classification

## 1. Digital Attack Surface Formulation
The Attack Surface $\mathcal{AS}_d$ of device $d$ is the composite set of all ingress points:
$$\mathcal{AS}_d = \bigcup_{i \in \text{Interfaces}(d)} \left( \text{IP}_i \times \text{Exposure}(i) \right) \times \bigcup_{p \in \text{Ports}(d)} \left( p \times \text{Service}(p) \times \text{Vulns}(p) \right)$$

## 2. Exposure & Accessibility Matrix
| Exposure Tier | Exposure Factor ($E$) | Network Context | Default Accessibility |
|---|---|---|---|
| `EXTERNAL` | $1.0$ | Public WAN Interfaces (`203.0.113.x`) | `REACHABLE` from Internet |
| `DMZ` | $0.8$ | Publicly Accessible Ingress DMZ Servers (`192.168.1.10`) | `RESTRICTED` via Port Forwarding |
| `INTERNAL` | $0.3$ | Workstations / Internal Private LAN (`192.168.1.11`) | `RESTRICTED` to LAN Subnet |
| `UNKNOWN` | $0.5$ | Unclassified Assets | `UNREACHABLE` until audited |