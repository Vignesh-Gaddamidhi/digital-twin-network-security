# Day 8: TCP Client-Server Operational Lifecycle

## 1. Architectural Model
The standard TCP server implements a bifurcated socket pattern:
1. **Listening Socket:** Binds to `0.0.0.0:5000` or `127.0.0.1:5000`. Never transmits data; its sole responsibility is accepting incoming connections.
2. **Connection Sockets:** Dedicated file descriptors spawned per client upon `accept()`. Handles bidirectional read/write operations independently.

## 2. Low-Level Error Analysis & Mitigations
- **`WSAEADDRINUSE` (Address already in use / Error 10048):** Occurs when a socket is bound to a port in `TIME_WAIT` state.
  - *Fix:* `sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)` prior to `bind()`.
- **`WSAECONNREFUSED` (Connection refused / Error 10061):** Port is unreachable or no process is listening on the target IP/Port. Target kernel returns `RST-ACK`.
- **`WSAECONNRESET` (Connection reset by peer / Error 10054):** Remote endpoint forcefully terminated connection without completing 4-Way FIN teardown.