# Day 10: Packet Structures & Binary Header Alignment

## 1. Frame & Header Specifications

### Ethernet II Frame
- **Preamble / SFD:** 8 Bytes (Layer 1 synchronization).
- **Destination MAC:** 6 Bytes (48 bits).
- **Source MAC:** 6 Bytes (48 bits).
- **EtherType:** 2 Bytes (`0x0800` = IPv4, `0x0806` = ARP, `0x86DD` = IPv6).
- **Trailer (FCS):** 4 Bytes CRC32.

### IPv4 Header (RFC 791)
- **Version (4 bits) + IHL (4 bits):** Header length in 32-bit words (default = 5 -> 20 bytes).
- **Type of Service / DSCP / ECN:** 1 Byte QoS markings.
- **Total Length:** 2 Bytes (entire packet size including headers and payload).
- **Identification, Flags, Fragment Offset:** 4 Bytes used for MTU packet fragmentation.
- **Time to Live (TTL):** 1 Byte hop limiter (decremented by routers).
- **Protocol:** 1 Byte (`1` = ICMP, `6` = TCP, `17` = UDP).
- **Header Checksum:** 2 Bytes validation over L3 header only.
- **Source & Destination Addresses:** 4 Bytes each (32 bits).

### TCP Header (RFC 793)
- **Source / Destination Ports:** 2 Bytes each (0 - 65535).
- **Sequence Number:** 4 Bytes (32 bits).
- **Acknowledgment Number:** 4 Bytes (32 bits).
- **Data Offset + Reserved:** 1 Byte (TCP header length).
- **Control Flags:** 1 Byte (`URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN`).
- **Window Size:** 2 Bytes (receiver flow-control buffer capacity).
- **Checksum:** 2 Bytes calculated over pseudo-header + TCP segment.