# Day 23: Service & Port Modeling Specification

## 1. Port Model (`PortEntity`)
Represents an open socket descriptor bound to an interface:
- `port_number`: 1 to 65535.
- `protocol`: `TCP` or `UDP`.
- `state`: `OPEN`, `FILTERED`, `CLOSED`.
- `is_exposed`: Boolean denoting reachability from untrusted / external subnets.

## 2. Service Model (`ServiceEntity`)
Represents the software process serving incoming requests on a port:
- `name`: Daemon process identifier (e.g., `nginx`, `sshd`, `dnsmasq`).
- `version`: Precise semantic version (e.g., `1.24.0`, `OpenSSH 8.9p1`).
- `status`: `RUNNING`, `STOPPED`, `DEGRADED`.
- `associated_cves`: List of unpatched vulnerabilities directly targeting this daemon.