# Day 16 Deliverable: Canonical Asset Attack Surface & Risk Matrix

| Asset ID | Device Label | Attack Surface (Listening Ports) | Network Exposure | Highest CVE | Criticality | Exposure Factor | Active Mitigation | Calculated Risk | Risk Level |
|---|---|---|---|---|---|---|---|---|---|
| `D001` | `ws-pc-01` | None (Client ephemeral outbound only) | Internal LAN (`192.168.1.0/24`) | `CVE-2024-21413` (CVSS 9.8) | 4.0 | 0.2 (Low) | Host firewall active (0.2) | **12.5** | **LOW** |
| `D002` | `srv-web-01` | 80/TCP (HTTP), 443/TCP (HTTPS), 22/TCP (SSH) | DMZ / Public Ingress | `CVE-2023-38408` (CVSS 9.8) | 8.5 | 1.0 (High) | Port 80/443 ACL (0.3) | **58.3** | **HIGH** |
| `D003` | `ws-pc-02` | None (Client ephemeral outbound only) | Internal LAN (`192.168.1.0/24`) | None (Baseline OS: 1.0) | 6.0 | 0.2 (Low) | Subnet segmentation (0.2) | **1.0** | **LOW** |
| `D004` | `rtr-gw-01` | 53/UDP (DNS), 67/UDP (DHCP), 22/TCP (SSH) | Perimeter Gateway (WAN + LAN) | Weak SSH Config (CVSS 7.5) | 9.5 | 1.0 (High) | Stateful NAT/Firewall (0.4) | **42.8** | **MEDIUM** |
| `D005` | `sw-core-01` | Layer-2 CAM bridging table | Internal Switching Fabric | CAM Flooding Limit (CVSS 5.0) | 9.0 | 0.3 (Medium) | Local broadcast boundary (0.2) | **10.8** | **LOW** |

## Key Insights
1. **D002 (Web Server)** has the highest risk score (**58.3 - HIGH**) despite router criticality being higher, because it combines public exposure ($E = 1.0$) with an exposed, unpatched RCE vulnerability (`CVE-2023-38408`).
2. **D001 (Workstation 1)** holds a high-severity CVE (9.8), but its internal LAN isolation ($E = 0.2$) and lack of listening service ports reduce its active score to **12.5 (LOW)**.