# Day 1: TCP/IP Model & Internet Protocol Architecture

## 1. TCP/IP Four-Layer Hierarchy
- **Application Layer:** Merges OSI Layers 5, 6, and 7. Operates strictly in user-space execution.
- **Transport Layer:** Coordinates multiplexed port sockets using TCP (connection-oriented, guaranteed delivery) or UDP (connectionless, datagram).
- **Internet Layer:** Operates packet switching via IP routing tables; ignores transport layer state.
- **Network Access Layer:** Combines OSI Layers 1 and 2; operates network interface cards (NICs), drivers, and Ethernet frames.

## 2. PDU Hierarchy
| Level | Layer | PDU Name | Identifiers |
|---|---|---|---|
| L4 | Transport | Segment (TCP) / Datagram (UDP) | Port Numbers (0-65535) |
| L3 | Internet | Packet | IPv4 / IPv6 Addresses |
| L2 | Network Access | Frame | 48-bit MAC Addresses |
| L1 | Network Access | Bit / Symbol | Binary signals |