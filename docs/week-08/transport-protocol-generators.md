# Day 52: Low-Level Transport Protocol Generators (TCP, UDP, ICMP)

## 1. TCP Connection Lifecycle Simulation
TCP requires explicit state transition tracking across communicating endpoints:
- `NEW`: Socket initialized.
- `CONNECTING`: 3-way handshake initiated (`SYN` sent).
- `ESTABLISHED`: Socket connected, data frame transmission active (`ACK`).
- `CLOSING`: Teardown sequence started (`FIN`).
- `CLOSED`: Gracefully terminated.
- `FAILED`: Abrupt termination (`RST`, socket timeout, or dropped handshake).

## 2. UDP Datagram Generator
UDP is transactional and connectionless:
- No session negotiation or acknowledgment overhead.
- Independent transmission bursts characterized by `(srcPort, dstPort, payloadBytes)`.

## 3. ICMP Diagnostics Generator
Network diagnostic messages:
- `ECHO_REQUEST`: Ping probe (Type 8, Code 0).
- `ECHO_REPLY`: Ping acknowledgment (Type 0, Code 0).
- `DESTINATION_UNREACHABLE`: Network/host/port drop notification (Type 3).
- `TIME_EXCEEDED`: Traceroute TTL decrement drop (Type 11).

## 4. Unified Traffic Event Schema
```json
{
  "eventId": "evt-001",
  "simulationId": "sim-001",
  "timestamp": "2026-09-08T14:45:00.000000Z",
  "sourceDevice": "client-01",
  "destinationDevice": "server-01",
  "protocol": "TCP",
  "sourcePort": 52000,
  "destinationPort": 443,
  "bytes": 1200,
  "packets": 1,
  "direction": "OUTBOUND",
  "tcpState": "ESTABLISHED"
}
}