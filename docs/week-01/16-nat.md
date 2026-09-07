# Day 6: Network Address Translation (NAT) & PAT State Engines

## 1. NAT Modes
- **Static NAT (1:1):** Maps one private IP directly to one public IP (commonly used for publicly exposed web servers).
- **Dynamic NAT (M:N):** Maps private IPs to a pool of public IPs on a first-come, first-served basis.
- **PAT / NAT Overload (M:1):** Multiple private IPs share a single public IP, distinguished using unique Layer-4 source port numbers (49152 - 65535).

## 2. NAT Connection Table Tracking
| Inside Local (Client) | Inside Global (Public Router) | Outside Global (Server) | Outside Local | Protocol | State |
|---|---|---|---|---|---|
| `192.168.1.11:51234` | `203.0.113.5:41002` | `93.184.216.34:443` | `93.184.216.34:443` | TCP | ESTABLISHED |