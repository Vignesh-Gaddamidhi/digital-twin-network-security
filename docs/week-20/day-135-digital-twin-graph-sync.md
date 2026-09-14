# Day 135: Build Security-Aware Digital Twin Graph & Synchronization

## 1. Single Source of Truth Principle
The Attack Path Graph does not maintain isolated asset inventories. All nodes, interfaces, services, and vulnerabilities are dynamically synchronized from the primary Digital Twin registry (`TwinSecurityGraphSynchronizer`).

## 2. Network Zones & Directed Reachability
- **`INTERNET`**: Untrusted external adversary ingress.
- **`DMZ`**: Demilitarized zone application servers (`WEB-01`).
- **`INTERNAL`**: Corporate workstations and internal services (`CLIENT-01`, `DNS-SERVER-01`).
- **`DATABASE`**: Isolated data repositories (`DB-01`).
- **`MANAGEMENT`**: Out-of-band administration networks.

## 3. Edge Security Controls & Reachability States
Edges maintain reachability classifications:
- `REACHABLE`: Open port, active service, firewall permitted.
- `RESTRICTED`: Port permitted only from designated source IP or role.
- `BLOCKED`: Explicitly dropped by firewall policy or network isolation.
- `UNKNOWN`: Unverified telemetry state.