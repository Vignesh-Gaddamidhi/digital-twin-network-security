# Day 3: Address Resolution Protocol (ARP) Mechanics

## 1. Role in the Stack
ARP bridges OSI Layer 3 (Logical IP) and OSI Layer 2 (Physical Ethernet MAC).
Routers and switches do not deliver frames using IP addresses; frame transmission on a local segment strictly requires a Destination MAC address.

## 2. Packet Structure (RFC 826)
- **Hardware Type (HTYPE):** `1` for Ethernet.
- **Protocol Type (PTYPE):** `0x0800` for IPv4.
- **Hardware Address Length:** `6` (bytes).
- **Protocol Address Length:** `4` (bytes).
- **Operation Code (OP):** `1` = ARP Request, `2` = ARP Reply.

## 3. Attack Scenarios Simulated in Digital Twin
- **ARP Spoofing / Poisoning:** Injecting forged ARP replies to associate the attacker MAC with the default gateway IP, redirecting host traffic through an attacker-controlled digital twin node (Man-in-the-Middle).