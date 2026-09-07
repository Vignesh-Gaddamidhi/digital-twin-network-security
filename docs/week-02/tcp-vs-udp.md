# Day 9: Architectural Comparison — TCP vs. UDP

| Dimension | TCP (`SOCK_STREAM`) | UDP (`SOCK_DGRAM`) |
|---|---|---|
| **Connection State** | Explicit (SYN, ESTABLISHED, TIME_WAIT) | Stateless (No state maintained in kernel) |
| **Reliability** | Guaranteed (ACK + Automatic Retransmit) | Best-effort (Lost packets are discarded) |
| **Data Framing** | Continuous stream (Requires framing headers) | Atomic datagrams (Boundaries preserved) |
| **Header Overhead** | 20–60 Bytes | 8 Bytes fixed |
| **Flow & Congestion Control**| Yes (Sliding window, AIMD algorithms) | None (Transmits at application speed) |
| **Delivery Ordering** | Guaranteed sequence ordering | Packets may arrive out-of-order or duplicate |
| **Digital Twin Use Case** | Web Admin, SSH consoles, DB sessions | NetFlow telemetry, Syslog, DNS emulation |