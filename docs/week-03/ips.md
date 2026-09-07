# Day 17: Intrusion Prevention Systems (IPS) Architecture

## 1. Active Enforcement Mechanics
- **Inline Placement:** Traverses the direct transit route between subnets or perimeter gateways.
- **Enforcement Primitives:**
  - **Packet Drop:** Discards frames silently at the NIC buffer layer.
  - **TCP Reset Injection:** Injects synthetic `RST` packets to both client and server to terminate active socket state tables immediately.
  - **Dynamic Blacklisting:** Instructs the perimeter router or firewall to inject temporary egress block rules (`iptables -I INPUT -s <attacker_ip> -j DROP`).

## 2. Tuning & Failure Modes
- **False Positive Hazard:** A false positive on an IDS creates a spurious alert; a false positive on an IPS disrupts critical business transactions (denial of service against legitimate traffic).
- **Bypass Safeguards:** Modern IPS architectures feature hardware bypass relays or fail-open NIC configurations to prevent complete network outages during engine crashes.