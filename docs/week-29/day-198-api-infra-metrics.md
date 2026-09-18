# Day 198: Detailed API & Infrastructure Metric Instrumentation

## 1. Automated ASGI Prometheus Middleware
The `PrometheusMiddleware` intercepts all incoming HTTP requests within the ASGI pipeline:
- **Duration Tracking**: Uses monotonic `time.perf_counter()` to record accurate response latencies without clock drift.
- **In-Flight Concurrency**: Manages the `api_active_requests` gauge via increment at start and decrement in `finally` blocks.
- **Route Normalization**: Parameterized route segments are converted to `{id}` templates, preventing cardinality bloat.
- **Scrape Filter**: Bypasses `/metrics` to avoid skewing telemetry observations with scraper requests.

## 2. Database Connection Pool Metrics
Tracked via `InfrastructureMetricsCollector`:
- `db_pool_active`: Connections currently allocated to in-flight SQL queries.
- `db_pool_idle`: Free connections available in the queue.
- `db_pool_max_size`: Configured maximum limit of the connection pool.
- `db_query_duration_seconds`: Histogram measuring execution duration of database queries.

## 3. Redis Telemetry & Cache Metrics
- `redis_connected_clients`: Active TCP client connections open on the Redis server.
- `redis_used_memory_bytes`: Memory allocated by the Redis instance.
- `redis_stream_length{stream="..."}`: Depth of Redis streams (e.g. `telemetry`, `simulation`, `alerts`).
- `redis_cache_hits_total` / `redis_cache_misses_total`: Hit/miss counters for measuring cache efficiency.

## 4. Host Runtime Metrics
Collected through direct OS process introspection:
- `process_cpu_percent`: Process CPU utilization percentage.
- `process_memory_rss_bytes`: Resident Set Size (RSS) memory consumption in bytes.
- `process_threads_count`: Number of active execution threads.