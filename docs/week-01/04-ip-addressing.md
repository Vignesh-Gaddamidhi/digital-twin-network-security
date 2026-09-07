# Day 2: IP Addressing & Subnet Architecture

## 1. IPv4 vs MAC Relationship
- **MAC Address:** Node identity inside a local link-layer broadcast domain (Hop-to-Hop).
- **IP Address:** Hierarchical logical location enabling packet delivery across intermediate networks (End-to-End).

## 2. Special & RFC 1918 Private Ranges
- `10.0.0.0/8`: Large enterprises (16,777,216 addresses).
- `172.16.0.0/12`: Medium networks (1,048,576 addresses).
- `192.168.0.0/16`: Local subnet environments (65,536 addresses).
- `127.0.0.1/8`: Loopback interface for local inter-process communication.
- `169.254.0.0/16`: APIPA (Automatic Private IP Addressing assigned on DHCP failure).

## 3. Broadcast Domains
- Switches delimit collision domains.
- Routers delimit broadcast domains. A broadcast packet (`255.255.255.255` or `FF:FF:FF:FF:FF:FF`) will not be routed past Layer 3 boundaries.