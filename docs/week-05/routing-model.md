# Day 32: Router Behavioral Model & Longest-Prefix Matching

## 1. Router Entity Specification
A router is a specialized network device that inspects Layer 3 packet headers and makes forwarding decisions based on an internal routing table.

### Core Attributes
- `routingTable`: Collection of active forwarding rules.
- `forwardingEnabled`: Boolean flag controlling IPv4 forwarding (`ip_forward`).
- `defaultGateway`: Fallback next hop when no specific subnet prefix matches.

## 2. Route Entry Contract
| Field | Type | Description |
|---|---|---|
| `destination` | String (CIDR) | Destination subnet mask (e.g., `192.168.1.0/24`, `0.0.0.0/0`) |
| `nextHop` | Optional[String] | IP of intermediate router, or `DIRECT` for local subnet |
| `interface` | String | Egress NIC (e.g., `eth0`, `eth1`, `wan0`) |
| `metric` | Integer | Administrative cost/distance (lower is preferred) |
| `status` | Enum | `ACTIVE`, `DISABLED`, `UNREACHABLE` |

## 3. Forwarding Algorithm (LPM)
Given destination IP $D$:
$$\text{BestRoute} = \arg\max_{r \in R, \, D \in r.\text{net}} \left( r.\text{prefix\_len} \times 1000 - r.\text{metric} \right)$$