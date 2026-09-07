# Day 16: Attack Surface Enumeration & Reduction Principles

## 1. Components of Network Attack Surface
- **Network Endpoints:** Active IPv4/IPv6 interfaces connected to physical or virtual switches.
- **Transport Ports:** Open TCP/UDP listening ports (`netstat -ano`).
- **Application Daemons:** Services bound to listening ports (Nginx, OpenSSH, PostgreSQL).
- **Inter-Subnet Traversal:** Routing hops that allow traffic to cross from untrusted to trusted zones.

## 2. Attack Surface Reduction Techniques
- Bind internal services strictly to loopback (`127.0.0.1`) or private management subnets rather than `0.0.0.0`.
- Enforce default-deny firewall policies on ingress perimeter gateways.
- Close unused or legacy protocol ports (e.g., Telnet on 23, FTP on 21).