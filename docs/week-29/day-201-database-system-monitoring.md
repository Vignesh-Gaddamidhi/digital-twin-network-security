# Day 201: PostgreSQL, API Infrastructure & System Resource Monitoring

## 1. Database Latency Decomposition
Database performance is tracked across two distinct execution boundaries:
1. `db_query_latency_seconds`: Raw query execution time on the PostgreSQL server.
2. `db_repo_e2e_latency_seconds`: Full data-access latency ($\text{API Call} \to \text{Repository Method} \to \text{Connection Acquisition} \to \text{PostgreSQL Exec} \to \text{Entity Hydration}$).

Tracked signals:
- `db_health`: Subsystem state (`HEALTHY`, `DEGRADED`, `UNAVAILABLE`, `ERROR`).
- `db_pool_active` / `db_pool_idle` / `db_pool_max_size`: Connection pool saturation.
- `db_slow_queries_total`: Count of queries exceeding the $100\text{ms}$ SLA threshold.
- `db_transactions_total` / `db_transaction_failures_total`: Completed vs. rolled back transactions.

## 2. API Infrastructure Error Stratification
Monitors gateway stability without grouping unrelated errors:
- `api_client_errors_total`: $4\text{xx}$ responses (e.g. invalid inputs, unauthorized, forbidden).
- `api_server_errors_total`: $5\text{xx}$ responses (unhandled exceptions, internal crashes).
- `api_timeouts_total`: HTTP $408$ / $504$ and gateway timeout events.

## 3. Hardware & Memory Monitoring
Live platform resource consumption metrics:
- `host_cpu_percent`: Host CPU utilization percentage.
- `host_memory_percent`: Overall host physical memory usage percentage.
- `host_memory_used_bytes` / `host_memory_available_bytes`: Raw memory allocations.
- `worker_memory_rss_bytes`: Resident Set Size allocated by active worker processes.

## 4. System Resource Correlation Cascade
The platform correlates resource pressure across subsystems to identify systemic bottlenecks:
HOST CPU / MEMORY PRESSURE (>= 85%)
                   │
                   ▼
       WORKER PROCESS EXECUTION SLOWS
                   │
                   ▼
       JOB PROCESSING RATE DROPS
                   │
                   ▼
   STREAM INGESTION BACKLOG BUILDS UP
                   │
                   ▼
 WEBSOCKET LIVE BROADCAST LATENCY SPIKES

Rather than presenting metrics in isolation, the correlation engine links high memory and CPU utilization to increased queue backlogs and higher WebSocket delivery latencies.