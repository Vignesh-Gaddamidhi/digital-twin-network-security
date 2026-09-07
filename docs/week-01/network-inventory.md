# Week 1 Capstone Deliverable: Authoritative Digital Twin Asset Registry

| Device ID | Hostname | Layer-3 IPv4 | Layer-2 MAC Address | Subnet Zone | Role / Purpose | Open Ports / Services | Oper State | Asset Criticality |
|---|---|---|---|---|---|---|---|---|
| `D001` | `ws-pc-01` | `192.168.1.11` | `00:50:56:FE:01:11` | `192.168.1.0/24` | Engineering Workstation (PC1) | None (Outbound Only) | ONLINE | 4.0 / 10 |
| `D002` | `srv-web-01` | `192.168.1.10` | `00:50:56:FE:01:10` | `192.168.1.0/24` | Production Application Server | 80/TCP (HTTP), 443/TCP (HTTPS), 22/TCP (SSH) | ONLINE | 8.5 / 10 |
| `D003` | `ws-pc-02` | `192.168.1.12` | `00:50:56:FE:01:12` | `192.168.1.0/24` | Finance Workstation (PC2) | None (Outbound Only) | ONLINE | 6.0 / 10 |
| `D004` | `rtr-gw-01` | `192.168.1.1` | `00:50:56:FE:01:00` | `192.168.1.0/24` | Gateway Router / NAT Perimeter | 53/UDP (DNS), 67/UDP (DHCP), 22/TCP (SSH) | ONLINE | 9.5 / 10 |
| `D005` | `sw-core-01`| Unnumbered | `00:50:56:FE:01:FE` | `192.168.1.0/24` | Layer-2 Bridging Fabric (Switch) | None (Hardware CAM table) | ONLINE | 9.0 / 10 |

## Topology Relationship Graph
- `D001` (ws-pc-01:eth0) <───> `D005` (sw-core-01:Port 1)
- `D002` (srv-web-01:eth0) <─> `D005` (sw-core-01:Port 2)
- `D003` (ws-pc-02:eth0) <───> `D005` (sw-core-01:Port 3)
- `D004` (rtr-gw-01:eth0) <──> `D005` (sw-core-01:Port 4)
- `D004` (rtr-gw-01:eth1) <──> Internet Transit Uplink (`203.0.113.5`)