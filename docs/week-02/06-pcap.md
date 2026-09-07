# Day 11: PCAP (Packet Capture) File Format & Storage Mechanics

## 1. Binary Structure
- **Global Header (24 Bytes):**
  - `magic_number` (`0xa1b2c3d4`): Determines endianness and microsecond vs. nanosecond time resolution.
  - `version_major` & `version_minor`: Usually 2.4.
  - `snaplen`: Maximum number of octets captured per packet (default 65535).
  - `network`: Data link type (`1` = Ethernet).
- **Packet Record Header (16 Bytes per packet):**
  - `ts_sec` & `ts_usec`: Epoch timestamp down to microsecond precision.
  - `incl_len`: Number of bytes saved in the file for this packet.
  - `orig_len`: Actual length of the packet when transmitted over the wire.

## 2. Role in Digital Twin Security Systems
- **Deterministic Replay:** Allows feeding identical captured attack traces through different ML models to evaluate classification accuracy.
- **Offline Telemetry Source:** Provides non-blocking packet feed for training anomaly detectors without impacting running host NICs.