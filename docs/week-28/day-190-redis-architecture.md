# Day 190: Redis Architecture & Infrastructure Foundation

## 1. Architectural Responsibility Matrix
Week 28 introduces Redis as a high-speed volatile event bus alongside Neon PostgreSQL:

| Subsystem | Primary Responsibility | Backing Storage | Data Retention |
|---|---|---|---|
| **PostgreSQL (:5432)** | Durable historical source of record, compliance audits, relational graph inventory | Neon Cloud Cluster | Permanent |
| **Redis (:6379)** | Sub-millisecond stream ingestion, ephemeral state, pub/sub fan-out, NetFlow cache | Memory / Ring-Buffer | Volatile / TTL |
| **Digital Twin** | Authoritative in-memory topological runtime model and node state registry | Python State Engine | Process Lifetime |
| **FastAPI Gateway (:8000)** | Ingestion controllers, Stream consumer workers, REST & WebSocket hub | Async Event Loop | Stateless |

## 2. Redis Primitives & Workload Separation
- **Redis Streams (`XADD`, `XREAD`, `XRANGE`)**:
  - `cybertwin:stream:telemetry`: High-frequency device CPU, memory, and packet rates.
  - `cybertwin:stream:events`: Suricata signatures and NetFlow tuples.
  - `cybertwin:stream:simulation`: Synthetic attack event logs.
  - Ring buffer capped at `maxlen=10000` to prevent memory saturation.
- **Redis Pub/Sub (`PUBLISH`, `SUBSCRIBE`)**:
  - `cybertwin:channel:realtime`: Client-facing WebSocket broadcasts.
- **Key-Value Cache with TTL (`SETEX`, `GET`)**:
  - NetFlow summaries (TTL: 60s).
  - Rate limiting and deduplication tokens (TTL: 5s).

## 3. Failure Distinction & Degradation Rules
- **`REDIS_HEALTHY`**: Full real-time stream processing enabled.
- **`REDIS_UNAVAILABLE` / `REDIS_CONNECTION_ERROR`**: FastAPI WebSocket gateway degrades to direct Twin polling.
- **`POSTGRESQL_DISCONNECTED`**: Freeze dashboard in monochromatic gray; display `PRIMARY PERSISTENCE LAYER DISCONNECTED`.
- **No Hallucination**: No synthetic metrics are generated under failure conditions.