# Day 197: Observability Architecture & Prometheus Foundation

## 1. Overview
Week 29 establishes platform observability across the three standard pillars: **Metrics**, **Traces**, and **Logs**. The primary target is continuous telemetry scraping via Prometheus on port `:9090`, feeding Grafana for visualization and real-time alerts.

                       CYBERTWIN PLATFORM
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                  │
            ▼                  ▼                  ▼
         FastAPI             Redis           PostgreSQL
            │                  │                  │
            └──────────────────┼──────────────────┘
                               │
                      OpenTelemetry / Core
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
         Metrics             Traces             Logs
            │                  │                  │
            └──────────────────┼──────────────────┘
                               ▼
                        Prometheus :9090
                               │
                               ▼
                       Grafana Dashboards

## 2. Core Metrics Definition
The platform exposes golden signals on `/metrics`:
- `api_requests_total`: Counter partitioned by `method`, `route`, `status_code`, and `service`.
- `api_errors_total`: Counter tracking client (4xx) and server (5xx) failures.
- `api_active_requests`: Gauge measuring concurrent transactions.
- `api_request_duration_seconds`: Histogram measuring execution duration with standard latency buckets:
  `[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]`
- `cybertwin_service_health`: Gauge (`1` = Healthy, `0` = Degraded/Down) per subsystem.
- `cybertwin_service_latency_milliseconds`: Gauge measuring raw round-trip latency to each dependency.

## 3. Cardinality Management Rules
To safeguard memory against high cardinality explosions:
1. Dynamic identifiers (`DEV-001`, `SIM-4091`, UUIDs) are normalized to `{id}` in all metric label dimensions.
2. Arbitrary parameters such as search tokens, IP addresses, and user IDs are strictly excluded from label sets.

## 4. Subsystem Health States
Health states are computed dynamically:
- `HEALTHY`: Functional, responding within SLA thresholds (<100ms).
- `DEGRADED`: Functional but elevated latency or partial worker pool availability.
- `UNAVAILABLE`: Socket, connection pool, or host unreachable.
- `ERROR`: Subsystem raising unhandled internal exceptions.
- `UNKNOWN`: Uninitialized or unpolled subsystem state.

## 5. Prometheus Scrape Configuration (`prometheus.yml`)
```yaml
global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: "cybertwin-api"
    metrics_path: "/metrics"
    static_configs:
      - targets: ["localhost:8000"]
        labels:
          environment: "production"
          cluster: "soc-core"