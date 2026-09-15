# Day 163: FastAPI WebSocket Gateway & Connection Lifecycle Manager

## 1. Connection Lifecycle State Machine
The client-server transport state machine guarantees resilience over unstable network connections:

[DISCONNECTED] ──(Handshake)──> [CONNECTED] ──(Full TwinStateSnapshot)──> [LIVE_STREAMING]
▲                               │
│ (Network Failure)             │ (Heartbeat Check / Ping-Pong)
│                               ▼
[RECONNECTING] <──(Exponential Backoff: 1s, 2s, 4s, max 10s)


## 2. Reconnection Resynchronization Protocol
If a disconnect occurs while the Digital Twin simulation is active:
1. Client drops transport state to `DISCONNECTED` and initiates exponential backoff `RECONNECTING`.
2. Upon re-establishing the socket connection, the gateway immediately dispatches a fresh, full `TwinStateSnapshot`.
3. Client resets its local sequence counter to `snapshot.sequenceNumber`, invalidating any missed intermediary delta events (`events 501..520`).
4. Client resumes ingesting incremental delta frames without state corruption.

## 3. Idempotency & Out-of-Order Frame Protection
Every client maintains an in-memory ring buffer of the last 1,000 processed `(eventId, sequenceNumber)` pairs:
- If an incoming `sequenceNumber <= last_processed_sequence`, the packet is logged as a duplicate/stale frame and discarded.
- If an incoming `sequenceNumber > last_processed_sequence + 1`, a sequence gap is detected; the client requests an on-demand resync snapshot.