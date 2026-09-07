# Day 3: Dynamic Host Configuration Protocol (DHCP)

## 1. Four-Way DORA Handshake
1. **Discover:** Client broadcasts on UDP 67 to find available DHCP servers.
2. **Offer:** DHCP server reserves an IP from its pool and unicasts/broadcasts configuration options.
3. **Request:** Client broadcasts its acceptance of the offered address.
4. **Acknowledgment (ACK):** Server confirms the binding and sets the lease timer.

## 2. Essential DHCP Options
- `Option 1`: Subnet Mask.
- `Option 3`: Router / Default Gateway.
- `Option 6`: Domain Name Servers (DNS).
- `Option 51`: IP Address Lease Time.

## 3. Digital Twin Attack Vectors
- **DHCP Starvation:** Simulating rogue MAC addresses requesting all available leases in a pool to deny service to valid endpoints.
- **Rogue DHCP Server:** Simulating a secondary malicious server answering Discover requests faster with attacker-controlled DNS and Gateway options.