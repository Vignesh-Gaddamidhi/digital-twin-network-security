# Day 9: UDP Datagram Architecture & Socket Programming

## 1. Core Primitives
- **Connectionless Communication:** No handshake, virtual circuit, or teardown sequence.
- **Message Boundaries:** Each `sendto()` maps strictly to one `recvfrom()`.
- **Stateless Listener:** A single listening UDP socket on port `6000` can receive datagrams concurrently from thousands of unique client endpoints without multiplexing child descriptors.

## 2. Low-Level API Methods
| Function | Role | Parameter Signature |
|---|---|---|
| `socket(AF_INET, SOCK_DGRAM)` | Allocates datagram socket | Protocol set to UDP (`IPPROTO_UDP`) |
| `bind((ip, port))` | Binds to local interface | Required for servers; optional for ephemeral clients |
| `sendto(bytes, (ip, port))` | Transmits atomic envelope | Target address required for each transmission |
| `recvfrom(buffer_size)` | Reads next single datagram | Returns `(data_bytes, (sender_ip, sender_port))` |