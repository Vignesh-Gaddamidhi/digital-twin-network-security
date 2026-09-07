# Day 8: Python Socket Architecture & Kernel Subsystems

## 1. Socket Primitives
- **Socket Definition:** Operating system interface mapping user-space processes to Layer-4 transport drivers via an endpoint tuple: `(Protocol, Local IP, Local Port)`.
- **Address Families:**
  - `AF_INET`: IPv4 logical addressing.
  - `AF_INET6`: IPv6 logical addressing.
  - `AF_UNIX`: POSIX Local inter-process communication (IPC).
- **Socket Types:**
  - `SOCK_STREAM`: Connection-oriented TCP byte streams.
  - `SOCK_DGRAM`: Connectionless UDP datagram envelopes.
  - `SOCK_RAW`: Raw Layer-3/Layer-2 packet access (bypasses transport driver).

## 2. API Method Differences
| API Call | Execution Context | Kernel Behavior |
|---|---|---|
| `bind((ip, port))` | Server Only | Claims IP/Port tuple in kernel socket table. Fails if port is claimed without `SO_REUSEADDR`. |
| `listen(backlog)` | Server Only | Allocates SYN queue and Accept queue; sets TCP state to `LISTEN`. |
| `accept()` | Server Only | Blocks until connection established; returns new dedicated connection socket. |
| `connect((ip, port))`| Client Only | Initiates outbound 3-Way Handshake (`SYN`); kernel assigns ephemeral port. |
| `sendall(bytes)` | Both | Transmits complete buffer, looping automatically until all bytes enter kernel queue. |
| `recv(bufsize)` | Both | Reads up to `bufsize` bytes from incoming sliding window buffer. |