# Day 35: Firewalls, Network Zones & Security Boundary Enforcement

## 1. Network Zones & Trust Matrix
Zones segment computing nodes into isolated security domains:

| Zone ID | Zone Name | Trust Level | Typical Assets | Ingress Inbound Default |
|---|---|---|---|---|
| `zone-internet` | `INTERNET` | 0 | Untrusted public nodes | DENY all inbound |
| `zone-dmz` | `DMZ` | 2 | Web servers, reverse proxies | ALLOW 80/443 only |
| `zone-internal` | `INTERNAL` | 3 | Workstations, DNS, Active Directory | DENY from Internet |
| `zone-database` | `DATABASE` | 4 | Relational DBs, persistence tiers | ALLOW only from DMZ backend |
| `zone-mgmt` | `MANAGEMENT` | 5 | Bastion hosts, Out-of-band IPMI | ALLOW via secure jump host |

## 2. Firewall Rule Schema
| Field | Type | Description |
|---|---|---|
| `id` | String | Unique rule ID (`rule-001`) |
| `sourceZone` | Enum | Originating security zone |
| `destinationZone` | Enum | Target destination security zone |
| `protocol` | Enum | `TCP`, `UDP`, `ICMP`, `ANY` |
| `destinationPort` | Optional[Int] | Layer 4 destination port (or null for ANY) |
| `action` | Enum | `ALLOW`, `DENY`, `DROP` |
| `priority` | Int | Evaluation precedence (lower number = higher priority) |