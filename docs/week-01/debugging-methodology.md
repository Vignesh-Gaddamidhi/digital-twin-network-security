# Week 1 Capstone: 10-Stage Network Debugging Methodology

When a host (PC1: `192.168.1.11`) cannot reach a destination service (Server: `192.168.1.10:443`), execute diagnostics strictly from Layer 1 up to Layer 7:
[Stage 1: Physical / Link]     Is the link carrier active? (Cable connected, Wi-Fi link speed > 0 bps)
│
[Stage 2: NIC Interface]       Is the NIC enabled and bound? (Get-NetAdapter)
│
[Stage 3: IP Address]          Does host hold a valid IPv4 address? (Not 0.0.0.0 or 169.254.x.x APIPA)
│
[Stage 4: Subnet Boundary]     Is the target IP inside the local subnet? Compare using subnet mask bitwise AND.
│
[Stage 5: ARP Resolution]      Does the local host have the target/gateway MAC in ARP cache? (arp -a)
│
[Stage 6: Gateway Health]      Can the host reach its Default Gateway? (ping 192.168.1.1)
│
[Stage 7: Route Table]         Does the host/router have a valid route to target network? (route print -4)
│
[Stage 8: Firewall Filter]     Is an inbound/outbound firewall rule dropping the packet? (Get-NetFirewallRule)
│
[Stage 9: Port Listening]      Is the target service bound and listening on the destination port? (netstat -ano)
│
[Stage 10: Service Daemon]     Is the application process healthy and returning valid responses? (curl /health)


## Digital Twin Failure Emulation Rules
- **ARP Poisoned:** Packet routed to attacker MAC instead of real gateway MAC.
- **Port Closed:** Target host returns TCP RST-ACK.
- **Firewall Drop:** Packet dropped silently; client connection times out without response.