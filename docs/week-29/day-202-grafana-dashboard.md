# Day 202: Grafana Enterprise Monitoring Dashboard

## 1. Dashboard Overview
- **Title**: `CYBERTWIN — SYSTEM HEALTH`
- **UID**: `cybertwin-sys-health-v1`
- **Default Refresh**: `10s` (tuned to avoid unnecessary scraper thrashing while maintaining responsive visibility)
- **Time Range Controls**: `5m`, `15m`, `30m`, `1h`, `6h`, `24h`

## 2. Dashboard Sections & Panel Layout
The dashboard layout spans the following 12 operational sections:

                      SYSTEM HEALTH OVERVIEW (Stat)
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                     ▼
     API GOLDEN SIGNALS (Timeseries)        API ERRORS 4xx/5xx (Timeseries)
                │                                     │
                ▼                                     ▼
     POSTGRESQL POOL (Gauge)                DATABASE LATENCY & SLOW SQL
                │                                     │
                ▼                                     ▼
     REDIS & CACHE HIT RATIO                EVENT PIPELINE & DROPPED AUDIT
                │                                     │
                ▼                                     ▼
     DIGITAL TWIN TOPOLOGY                  ML INFERENCE & SHAP EXPLANATIONS
                │                                     │
                ▼                                     ▼
     SIMULATION EXPERIMENTS                 WEBSOCKET BROADCAST LATENCY
                │                                     │
                └──────────────────┬──────────────────┘
                                   ▼
                   HOST RESOURCES: CPU & MEMORY %

## 3. Core PromQL Query Mappings
1. **API Latencies**:
   - `histogram_quantile(0.50, sum(rate(api_request_duration_seconds_bucket[1m])) by (le))`
   - `histogram_quantile(0.95, sum(rate(api_request_duration_seconds_bucket[1m])) by (le))`
   - `histogram_quantile(0.99, sum(rate(api_request_duration_seconds_bucket[1m])) by (le))`
2. **Database Query Errors & Slow Queries**:
   - `rate(db_query_errors_total[1m])`
   - `rate(db_slow_queries_total[1m])`
3. **Event Stream Dropped Reasons**:
   - `sum(rate(events_dropped_total[1m])) by (reason)`
4. **WebSocket Distribution Latency**:
   - `histogram_quantile(0.95, sum(rate(ws_broadcast_latency_seconds_bucket[1m])) by (le))`
5. **Host Memory & CPU**:
   - `host_cpu_percent`
   - `host_memory_used_bytes / 1073741824`