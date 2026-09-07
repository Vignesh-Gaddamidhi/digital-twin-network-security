# Day 10: Mapping Raw Packets to Digital Twin Graph Telemetry

## 1. Abstraction Transformation
The Digital Twin cannot ingest raw binary wire bytes directly at scale. The raw stream must be normalized into typed state updates and edge connections:

RAW PACKET WIRE DATA                           DIGITAL TWIN TOPOLOGY GRAPH
[Ether | IP | TCP | Payload]                     (Node D001) ──[Active Connection]──► (Node D002)
│                                                                  │
▼                                                                  ▼
Scapy Dissector Fields                           Graph State Entity

IP.src  (192.168.1.11)          ───────►       - source_device: "D001"

IP.dst  (192.168.1.10)          ───────►       - destination_device: "D002"

IP.proto (6 -> TCP)             ───────►       - protocol: "TCP"

TCP.sport (50000)               ───────►       - source_port: 50000

TCP.dport (5000)                ───────►       - destination_port: 5000

TCP.flags ('S')                 ───────►       - connection_state: "SYN_SENT"

len(packet)                     ───────►       - byte_count: 74

packet.time                     ───────►       - last_observed: 2026-09-07T...


## 2. Dynamic State Impact
1. **Device Status Update:** When a node transmits or receives a packet, its `status` is confirmed `ONLINE`.
2. **Port State Discovery:** If a node responds with `SYN-ACK`, its destination port is marked `OPEN` in the twin registry.
3. **Attack Prediction Feature Extraction:** Sequence of rapid SYN packets with non-incrementing ACK updates the anomaly counter for port scanning.