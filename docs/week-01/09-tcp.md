# Day 4: Transmission Control Protocol (TCP) Deep Dive

## 1. Transmission Reliability Mechanics
- **Connection-Oriented:** Requires explicit state negotiation via the 3-Way Handshake (SYN -> SYN-ACK -> ACK).
- **Byte Sequencing:** Segments track `Sequence Number` (relative offset of transmitted bytes) and `Acknowledgment Number` (next expected incoming byte).
- **Flow Control (Sliding Window):** Receiver advertises its available buffer size in the `Window Size` header field to prevent buffer overflows.

## 2. Six Primary Control Flags
- `SYN`: Synchronize sequence numbers during connection establishment.
- `ACK`: Acknowledges received segments.
- `FIN`: Signals sender transmission closure.
- `RST`: Abruptly resets an invalid or rejected socket connection.
- `PSH`: Bypasses kernel buffers to push data directly to user-space application processes.
- `URG`: Flags segment data as high-priority out-of-band processing.

## 3. Digital Twin Threat Modeling
- **SYN Flood Attack:** Attacker generates thousands of SYN packets with forged source IPs without sending final ACKs, exhausting the host connection state table (Half-Open connections).
- **TCP Port Scanning (Half-Open / Stealth Scan):** Sends SYN; if SYN-ACK is returned, the port is open; sender immediately returns RST instead of ACK to avoid standard application-level logging.