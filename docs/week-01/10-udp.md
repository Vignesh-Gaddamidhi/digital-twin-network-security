# Day 4: User Datagram Protocol (UDP) Architecture

## 1. Stateless Datagram Mechanics
- **Connectionless:** No handshake, sequence tracking, or delivery guarantees.
- **Fixed 8-Byte Header:**
  - Source Port (16 bits)
  - Destination Port (16 bits)
  - Length (16 bits)
  - Checksum (16 bits)

## 2. Ideal Use Cases
- Low-latency real-time streaming (VoIP, Video, Online Gaming).
- Lightweight request-response mechanisms (DNS on port 53, DHCP on ports 67/68, SNMP on port 161).

## 3. Security Implications in Digital Twins
- **UDP Amplification Attacks:** Because UDP does not validate source IP addresses via a handshake, attackers spoof target IPs when querying open DNS or NTP resolvers, reflecting high-volume responses to flood victim hosts.