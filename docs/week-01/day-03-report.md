# Day 3 Deliverable: Subnet Architecture, ARP Lifecycle, and DHCP Analysis Report

## 1. Network Subnet Partitioning Plan
The Digital Twin primary environment is partitioned from `192.168.1.0/24` into three functional security zones:

| Zone Label | CIDR Subnet | Usable IP Scope | Gateway | Broadcast | Allocation Function |
|---|---|---|---|---|---|
| **DMZ Tier** | `192.168.1.0/26` | `192.168.1.1` - `192.168.1.62` | `192.168.1.1` | `192.168.1.63` | Public Web & Reverse Proxies |
| **Workstations** | `192.168.1.64/26` | `192.168.1.65` - `192.168.1.126` | `192.168.1.65` | `192.168.1.127` | Employee Endpoints (PC1, PC2) |
| **Secure Core DB**| `192.168.1.128/26`| `192.168.1.129` - `192.168.1.190`| `192.168.1.129`| `192.168.1.191`| Production Database Assets |

## 2. ARP Dissection Analysis
- **Request Opcode:** `1` (Broadcast to `FF:FF:FF:FF:FF:FF`).
- **Resolution Mapping:** `192.168.1.11` queries `192.168.1.10`.
- **Reply Opcode:** `2` (Unicast to `00:50:56:FE:01:11`).
- **Cache Lifecycle:** Dynamic entry persisted into Digital Twin CAM/ARP cache table with a 300-second aging timeout.

## 3. DHCP DORA Protocol Audit
- **Port Pair:** Client UDP 68 $\leftrightarrow$ Server UDP 67.
- **Client Transaction ID (XID):** `0x3903F326`.
- **Assigned Lease Parameters:**
  - Client Address: `192.168.1.75`
  - Subnet Mask: `255.255.255.192` (`/26`)
  - Default Gateway: `192.168.1.65`
  - DNS Server: `192.168.1.1`
  - Lease Duration: 86400 seconds (24 hours)