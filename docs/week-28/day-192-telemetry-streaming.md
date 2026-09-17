# Day 192: Telemetry & Digital Twin Event Streaming

## 1. Decoupled Asynchronous Telemetry Lineage
Day 192 replaces direct synchronous database writes with an event-driven Redis streaming architecture:
[Device Agent / Simulation Pulse]
│ (High-Frequency Microsecond Pulses)
▼
[Redis Stream: cybertwin:stream:telemetry]
│ (XADD ring buffer: maxlen 10000)
▼
[TwinEventConsumer]
│
┌───────┴───────────────────────────────┐
▼                                       ▼
[Authoritative Digital Twin Engine]     [Redis Ephemeral Cache]
• In-memory node state updates          • twin:device:{id}:latest
• Active link saturation metrics        • TTL: 60s snapshot
│                                       │
▼                                       ▼
[PostgreSQL Database (Neon Cloud)]      [WebSocket Gateway Channel]
• Durable historical record             • Sub-millisecond UI delta
• Async background write task           • Broadcast to Port 3000


## 2. Invariant Rules
1. **Digital Twin Authority**: The Digital Twin state engine remains the single source of state truth. The consumer updates the Twin graph; Redis provides transit and ephemeral caching.
2. **Ephemeral vs Durable Storage**:
   - **Redis**: High-frequency ephemeral key snapshots (`twin:device:{deviceId}:latest`) with a 60-second TTL.
   - **PostgreSQL**: Durable chronological telemetry history for deep forensic timeline inspection.
3. **At-Least-Once Delivery & Idempotency**: Redis Stream consumer groups track message ACKs (`XACK`) combined with 5-minute atomic deduplication keys (`cybertwin:dedup:{eventId}`) to eliminate duplicate state transitions.