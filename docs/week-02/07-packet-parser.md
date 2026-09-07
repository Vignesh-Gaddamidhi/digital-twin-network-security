# Day 11: Offline Packet Parsing & Protocol Detection Engine

## 1. Multi-Stage Pipeline
1. **Raw Frame Ingest:** Stream binary blobs using `scapy.utils.PcapReader` to process large PCAPs with minimal memory consumption.
2. **Layer Demultiplexing:** Traverse protocol stack pointers: `Ethernet -> IP/IPv6 -> TCP/UDP/ICMP -> L7 Payload`.
3. **Deep Payload Inspection (DPI):** Extract protocol flags (e.g., DNS opcodes, TLS ClientHello, HTTP methods).
4. **Structured Event Generation:** Output a standardized dictionary for normalization.