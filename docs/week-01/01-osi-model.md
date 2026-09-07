# Day 1: OSI Reference Model Architecture

## 1. The Seven Layers
- **Layer 7 (Application):** Direct interface to software network services (HTTP, DNS).
- **Layer 6 (Presentation):** Syntactic representation, compression, and cryptographic negotiation (TLS, ASCII).
- **Layer 5 (Session):** Inter-host dialogue control, multiplexing sessions, synchronization checkpoints.
- **Layer 4 (Transport):** End-to-end communication reliability, flow control, windowing (TCP/UDP).
- **Layer 3 (Network):** Logical addressing, route path selection, fragmentation across subnets (IPv4, IPv6, ICMP).
- **Layer 2 (Data Link):** Physical node-to-node transfer, media access control, error detection (Ethernet, ARP).
- **Layer 1 (Physical):** Bitstream transmission over physical mediums (electrical, optical, radio).

## 2. Digital Twin Implications
In our network security digital twin:
- Node models emulate L2/L3 identities (`macAddress`, `ipAddress`).
- Simulated links track L1/L4 constraints (`bandwidthMbps`, `latencyMs`, port bindings).
- Vulnerability evaluation maps to L7/L4 vulnerabilities (e.g., CVE-2023-38408 in OpenSSH).