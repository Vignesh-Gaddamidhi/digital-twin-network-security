# Day 8 Deliverable: Dissecting the TCP Socket Transaction

## 1. Frame-by-Frame Packet Breakdown (Port 5000 Capture)
Frame 1: TCP Handshake - SYN
Source IP: 127.0.0.1 (Client)        Destination IP: 127.0.0.1 (Server)
Source Port: 52145 (Ephemeral)       Destination Port: 5000 (Listen)
Sequence Number: 0 (Relative)        Ack Number: 0
Flags: 0x002 (SYN)
Window Size: 65535                   MSS Option: 65495 bytes

Frame 2: TCP Handshake - SYN-ACK
Source IP: 127.0.0.1 (Server)        Destination IP: 127.0.0.1 (Client)
Source Port: 5000                    Destination Port: 52145
Sequence Number: 0                   Ack Number: 1 (Client ISN + 1)
Flags: 0x012 (SYN, ACK)
Window Size: 65535                   MSS Option: 65495 bytes

Frame 3: TCP Handshake - ACK
Source IP: 127.0.0.1 (Client)        Destination IP: 127.0.0.1 (Server)
Source Port: 52145                   Destination Port: 5000
Sequence Number: 1                   Ack Number: 1 (Server ISN + 1)
Flags: 0x010 (ACK)                   Connection State: ESTABLISHED

Frame 4: Client Payload Transmission (PSH-ACK)
Source Port: 52145                   Destination Port: 5000
Flags: 0x018 (PSH, ACK)              Length: 39 Bytes
Payload String: "Hello Server - Digital Twin Session Sync"

Frame 5: Server ACK
Source Port: 5000                    Destination Port: 52145
Flags: 0x010 (ACK)                   Ack Number: 40 (1 + 39 bytes consumed)

Frame 6: Server Response Transmission (PSH-ACK)
Source Port: 5000                    Destination Port: 52145
Flags: 0x018 (PSH, ACK)              Length: 76 Bytes
Payload String: "ACK_FROM_SERVER: Received 'Hello Server...' at 2026-09-07T..."

Frame 7: Client ACK
Source Port: 52145                   Destination Port: 5000
Flags: 0x010 (ACK)                   Ack Number: 77 (1 + 76 bytes consumed)

Frame 8 - 11: Connection Teardown
Bidirectional exchange of [FIN, ACK] segments releasing kernel buffers.


## 2. Digital Twin Implications
- **SYN Backlog Modeling:** In future weeks, our simulation engine will track `SYN_RECV` states inside the Digital Twin graph to calculate threshold exhaustion during SYN-flood attack scenarios.
- **Payload Inspection:** Extracting payload bytes directly from socket descriptors simulates telemetry logging before passing records to Zeek/Suricata IDS parsers.