# Day 3: Subnetting Mathematics & Variable Length Subnet Masking (VLSM)

## 1. Bit Allocation Mechanics
- Every IPv4 address comprises 32 bits: Network bits + Host bits.
- Subnet mask bits set to `1` identify the network boundary; bits set to `0` designate host space.
- Usable Host Formula: $2^{(32 - \text{CIDR})} - 2$.

## 2. Standard Practice Reference Table
| CIDR | Subnet Mask | Total Addresses | Usable Hosts | Use Case |
|---|---|---|---|---|
| `/30` | `255.255.255.252` | 4 | 2 | Point-to-Point Router Links |
| `/28` | `255.255.255.240` | 16 | 14 | Small DMZ / Bastion Subnet |
| `/26` | `255.255.255.192` | 64 | 62 | Departmental Segments |
| `/24` | `255.255.255.0` | 256 | 254 | Standard Enterprise LAN Subnet |
| `/16` | `255.255.0.0` | 65,536 | 65,534 | Campus / Enterprise Core |

## 3. Digital Twin Implementation Role
In our Digital Twin Graph Engine:
- Networks are partitioned into logical subnets (`SubnetEntity`).
- Lateral movement simulations calculate cross-subnet traversal by checking router hop policies.