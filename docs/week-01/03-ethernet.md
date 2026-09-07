# Day 2: Ethernet Architecture & Link-Layer Mechanics

## 1. Physical & Data Link Interface
- **NIC (Network Interface Card):** Hardware controller responsible for physical serialization of frames into electrical/optical signals and frame checksum validation (FCS).
- **Ethernet II Frame Standard:** The dominant frame standard for TCP/IP communications.
- **EtherType Constants:**
  - `0x0800`: IPv4 Payload
  - `0x86DD`: IPv6 Payload
  - `0x0806`: Address Resolution Protocol (ARP)

## 2. Frame Processing Logic
1. NIC reads incoming electrical signal into an internal buffer.
2. Checks **Destination MAC**:
   - If Destination MAC matches NIC MAC, Broadcast (`FF:FF:FF:FF:FF:FF`), or registered Multicast $\to$ passes frame up to kernel.
   - If Destination MAC does not match $\to$ frame dropped immediately in silicon without CPU overhead (unless promiscuous mode is active).
3. FCS (Frame Check Sequence) is verified with CRC32. Corrupt frames are dropped.