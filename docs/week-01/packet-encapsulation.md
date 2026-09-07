# Day 1: Packet Encapsulation & Protocol Headers

## 1. Transmission Pipeline
1. Application layer writes an HTTP payload.
2. Transport layer attaches a 20-byte TCP header containing source/destination ports and sequence numbers.
3. Internet layer wraps the segment with a 20-byte IPv4 header containing TTL, protocol flags, and source/destination IP addresses.
4. Data Link layer prepends a 14-byte Ethernet header (Destination MAC, Source MAC, EtherType: 0x0800) and appends a 4-byte CRC32 frame check sequence (FCS).

## 2. Header Structure
- **Ethernet II Header:** 14 Bytes (6B Dst MAC + 6B Src MAC + 2B EtherType)
- **IPv4 Header (No Options):** 20 Bytes (Includes TTL, Header Checksum, Addresses)
- **TCP Header (No Options):** 20 Bytes (Includes Ports, Sequence, Ack, Flags, Window)
- **Minimum Overhead per Web Request:** 54 Bytes prior to application payload.