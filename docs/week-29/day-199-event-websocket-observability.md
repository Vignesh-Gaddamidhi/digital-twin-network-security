# Day 199: Redis, Event Pipeline & WebSocket Observability

## 1. Overview
Day 199 instruments the platform's event-driven architecture, capturing event throughput, consumer state, dropped-event taxonomy, and WebSocket distribution latencies.

   REDIS EVENT STREAM (Week 28)
                │
                ▼
       [PUBLISH TIMESTAMP]
                │
   ┌────────────┴────────────┐
   ▼                         ▼
[CONSUME TIMESTAMP]      [DROPPED EVENT]
│                         │
▼                         ▼
[WORKER PROCESS]         REASON TAXONOMY:
│                  - QUEUE_OVERFLOW
▼                  - TIMEOUT
[COMPLETE TIMESTAMP]      - INVALID_EVENT
- RESOURCE_LIMIT
- CONSUMER_FAILURE


## 2. Event Throughput & Counters
- `events_published_total{event_type, source}`: Count of events published to Redis Streams.
- `events_consumed_total{event_type, consumer, source}`: Ingested events per consumer.
- `events_failed_total{event_type, consumer, source}`: Processing failures.
- `events_dropped_total{event_type, source, reason}`: Explicitly categorized dropped events (no silent drops).

## 3. End-to-End Processing Latency
- `event_processing_latency_seconds`: Duration from consumption start to completion.
- `event_e2e_latency_seconds`: Duration from initial publication in Redis to final completion.

## 4. Consumer Health Registry
Tracks the six core consumers:
1. `twin_consumer`
2. `ml_consumer`
3. `alert_consumer`
4. `risk_consumer`
5. `attack_path_consumer`
6. `incident_consumer`

Status indicators:
- `IDLE`: Operational, waiting for messages.
- `PROCESSING`: Handling a batch of messages.
- `DEGRADED`: Backlog exceeds 1,000 unread messages.
- `STALLED`: Backlog exceeds 5,000 unread messages.

## 5. WebSocket Distribution Path
Tracks real-time delivery performance:
$$\text{Redis Event} \xrightarrow{\text{Pub/Sub}} \text{FastAPI Gateway} \xrightarrow{\text{Broadcast}} \text{WebSocket Client}$$

Monitored metrics:
- `ws_active_connections`: Gauge of connected SOC clients.
- `ws_broadcast_latency_seconds`: Time elapsed from Redis publication to WebSocket client transmission.
- `ws_client_state_count`: Distribution of clients across `CONNECTED`, `DISCONNECTED`, `RECONNECTING`, `SNAPSHOT_RESYNC`, and `LIVE` states.