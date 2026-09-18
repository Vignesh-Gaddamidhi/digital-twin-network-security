import time
import math
import asyncio
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple

class DropReasonEnum(str, Enum):
    QUEUE_OVERFLOW = "QUEUE_OVERFLOW"
    INVALID_EVENT = "INVALID_EVENT"
    CONSUMER_FAILURE = "CONSUMER_FAILURE"
    TIMEOUT = "TIMEOUT"
    SHUTDOWN = "SHUTDOWN"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    UNKNOWN = "UNKNOWN"

class ConsumerStatusEnum(str, Enum):
    IDLE = "IDLE"
    PROCESSING = "PROCESSING"
    STALLED = "STALLED"
    DEGRADED = "DEGRADED"
    STOPPED = "STOPPED"

class WebSocketClientStateEnum(str, Enum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    RECONNECTING = "RECONNECTING"
    SNAPSHOT_RESYNC = "SNAPSHOT_RESYNC"
    LIVE = "LIVE"

OBS_LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

class EventAndWebSocketObservability:
    """
    Central collector for event throughput, consumer state, dropped-event taxonomy,
    Redis stream lag, and WebSocket broadcast latency.
    """
    def __init__(self):
        # 1. Event throughput counters: (event_type, source) -> int
        self.events_published_total: Dict[Tuple[str, str], int] = {}
        # (event_type, consumer, source) -> int
        self.events_consumed_total: Dict[Tuple[str, str, str], int] = {}
        self.events_failed_total: Dict[Tuple[str, str, str], int] = {}
        # (event_type, source, reason) -> int
        self.events_dropped_total: Dict[Tuple[str, str, str], int] = {}

        # 2. Latency Histograms
        # (event_type, consumer) -> {buckets, sum, count, samples}
        self.event_processing_latency_hist: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.event_e2e_latency_hist: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # 3. Consumer health registry
        self.consumers: Dict[str, Dict[str, Any]] = {
            c: {
                "status": ConsumerStatusEnum.IDLE,
                "processed": 0,
                "failed": 0,
                "retries": 0,
                "avg_latency_ms": 0.0,
                "backlog": 0,
                "last_active": time.time()
            }
            for c in [
                "twin_consumer",
                "ml_consumer",
                "alert_consumer",
                "risk_consumer",
                "attack_path_consumer",
                "incident_consumer"
            ]
        }

        # 4. Redis connection & stream monitoring
        self.redis_cmd_latency_ms: float = 0.0
        self.redis_stream_lag: Dict[str, int] = {}
        self.redis_timeouts_total: int = 0
        self.redis_errors_total: int = 0

        # 5. WebSocket Monitoring
        self.ws_active_connections: int = 0
        self.ws_connections_opened_total: int = 0
        self.ws_connections_closed_total: int = 0
        self.ws_connection_errors_total: int = 0
        self.ws_messages_sent_total: int = 0
        self.ws_messages_failed_total: int = 0
        self.ws_reconnects_total: int = 0
        self.ws_client_states: Dict[WebSocketClientStateEnum, int] = {
            s: 0 for s in WebSocketClientStateEnum
        }
        self.ws_client_states[WebSocketClientStateEnum.DISCONNECTED] = 0

        # WebSocket broadcast latency: (topic) -> {buckets, sum, count, samples}
        self.ws_broadcast_latency_hist: Dict[str, Dict[str, Any]] = {}

    # ----------------- EVENT RECORDING -----------------

    def record_event_published(self, event_type: str, source: str = "internal"):
        key = (event_type, source)
        self.events_published_total[key] = self.events_published_total.get(key, 0) + 1

    def record_event_consumed(
        self,
        event_type: str,
        consumer: str,
        source: str,
        publish_timestamp: float,
        consume_timestamp: Optional[float] = None
    ) -> float:
        """
        Record start of event consumption. Returns current time to benchmark processing duration.
        """
        key = (event_type, consumer, source)
        self.events_consumed_total[key] = self.events_consumed_total.get(key, 0) + 1
        
        if consumer in self.consumers:
            c = self.consumers[consumer]
            c["status"] = ConsumerStatusEnum.PROCESSING
            c["last_active"] = time.time()

        return time.time()

    def record_event_completed(
        self,
        event_type: str,
        consumer: str,
        source: str,
        publish_timestamp: float,
        start_processing_time: float,
        failed: bool = False,
        retried: bool = False
    ):
        complete_time = time.time()
        proc_duration = max(0.0001, complete_time - start_processing_time)
        e2e_duration = max(0.0001, complete_time - publish_timestamp)

        # Update Consumer state
        if consumer in self.consumers:
            c = self.consumers[consumer]
            c["status"] = ConsumerStatusEnum.IDLE
            c["last_active"] = complete_time
            if failed:
                c["failed"] += 1
            else:
                c["processed"] += 1
            if retried:
                c["retries"] += 1
            c["avg_latency_ms"] = round((c["avg_latency_ms"] * 0.9) + (proc_duration * 1000.0 * 0.1), 2)

        key = (event_type, consumer, source)
        if failed:
            self.events_failed_total[key] = self.events_failed_total.get(key, 0) + 1

        # Record histograms
        hist_key = (event_type, consumer)
        self._add_to_hist(self.event_processing_latency_hist, hist_key, proc_duration)
        self._add_to_hist(self.event_e2e_latency_hist, hist_key, e2e_duration)

    def record_event_dropped(self, event_type: str, source: str, reason: DropReasonEnum):
        key = (event_type, source, reason.value)
        self.events_dropped_total[key] = self.events_dropped_total.get(key, 0) + 1

    def update_consumer_backlog(self, consumer: str, backlog_count: int):
        if consumer in self.consumers:
            self.consumers[consumer]["backlog"] = max(0, backlog_count)
            if backlog_count > 5000:
                self.consumers[consumer]["status"] = ConsumerStatusEnum.STALLED
            elif backlog_count > 1000:
                self.consumers[consumer]["status"] = ConsumerStatusEnum.DEGRADED

    # ----------------- WEBSOCKET RECORDING -----------------

    def record_ws_connection_opened(self, initial_state: WebSocketClientStateEnum = WebSocketClientStateEnum.CONNECTED):
        self.ws_active_connections += 1
        self.ws_connections_opened_total += 1
        self.ws_client_states[initial_state] = self.ws_client_states.get(initial_state, 0) + 1

    def record_ws_connection_closed(self, previous_state: WebSocketClientStateEnum = WebSocketClientStateEnum.CONNECTED):
        self.ws_active_connections = max(0, self.ws_active_connections - 1)
        self.ws_connections_closed_total += 1
        if previous_state in self.ws_client_states:
            self.ws_client_states[previous_state] = max(0, self.ws_client_states[previous_state] - 1)
        self.ws_client_states[WebSocketClientStateEnum.DISCONNECTED] = self.ws_client_states.get(WebSocketClientStateEnum.DISCONNECTED, 0) + 1

    def transition_ws_client_state(self, from_state: WebSocketClientStateEnum, to_state: WebSocketClientStateEnum):
        if from_state in self.ws_client_states:
            self.ws_client_states[from_state] = max(0, self.ws_client_states[from_state] - 1)
        self.ws_client_states[to_state] = self.ws_client_states.get(to_state, 0) + 1
        if to_state == WebSocketClientStateEnum.RECONNECTING:
            self.ws_reconnects_total += 1

    def record_ws_broadcast(self, topic: str, redis_timestamp: float, client_received_timestamp: Optional[float] = None, failed: bool = False):
        if failed:
            self.ws_messages_failed_total += 1
            return
        
        self.ws_messages_sent_total += 1
        t_recv = client_received_timestamp or time.time()
        b_latency = max(0.0001, t_recv - redis_timestamp)
        self._add_to_hist(self.ws_broadcast_latency_hist, topic, b_latency)

    def _add_to_hist(self, target_dict: Dict[Any, Dict[str, Any]], key: Any, val: float):
        if key not in target_dict:
            target_dict[key] = {
                "buckets": {b: 0 for b in OBS_LATENCY_BUCKETS},
                "sum": 0.0,
                "count": 0
            }
        h = target_dict[key]
        h["sum"] += val
        h["count"] += 1
        for b in OBS_LATENCY_BUCKETS:
            if val <= b:
                h["buckets"][b] += 1

    # ----------------- PROMETHEUS EXPOSITION -----------------

    def render_event_and_ws_exposition(self) -> str:
        lines = []

        # 1. Event Counters
        lines.append("# HELP events_published_total Total events published into Redis Streams.")
        lines.append("# TYPE events_published_total counter")
        for (et, src), cnt in self.events_published_total.items():
            lines.append(f'events_published_total{{event_type="{et}",source="{src}"}} {cnt}')

        lines.append("# HELP events_consumed_total Total events ingested by consumers.")
        lines.append("# TYPE events_consumed_total counter")
        for (et, cons, src), cnt in self.events_consumed_total.items():
            lines.append(f'events_consumed_total{{event_type="{et}",consumer="{cons}",source="{src}"}} {cnt}')

        lines.append("# HELP events_failed_total Total events resulting in processing errors.")
        lines.append("# TYPE events_failed_total counter")
        for (et, cons, src), cnt in self.events_failed_total.items():
            lines.append(f'events_failed_total{{event_type="{et}",consumer="{cons}",source="{src}"}} {cnt}')

        lines.append("# HELP events_dropped_total Total events dropped by platform with categorical reason.")
        lines.append("# TYPE events_dropped_total counter")
        for (et, src, rsn), cnt in self.events_dropped_total.items():
            lines.append(f'events_dropped_total{{event_type="{et}",source="{src}",reason="{rsn}"}} {cnt}')

        # 2. Event Latencies
        lines.append("# HELP event_processing_latency_seconds Time taken by consumer worker to complete event handling.")
        lines.append("# TYPE event_processing_latency_seconds histogram")
        for (et, cons), h in self.event_processing_latency_hist.items():
            acc = 0
            for b in OBS_LATENCY_BUCKETS:
                acc += h["buckets"][b]
                lines.append(f'event_processing_latency_seconds_bucket{{event_type="{et}",consumer="{cons}",le="{b}"}} {acc}')
            lines.append(f'event_processing_latency_seconds_bucket{{event_type="{et}",consumer="{cons}",le="+Inf"}} {h["count"]}')
            lines.append(f'event_processing_latency_seconds_sum{{event_type="{et}",consumer="{cons}"}} {round(h["sum"], 5)}')
            lines.append(f'event_processing_latency_seconds_count{{event_type="{et}",consumer="{cons}"}} {h["count"]}')

        lines.append("# HELP event_e2e_latency_seconds Total end-to-end duration from initial publication to completion.")
        lines.append("# TYPE event_e2e_latency_seconds histogram")
        for (et, cons), h in self.event_e2e_latency_hist.items():
            acc = 0
            for b in OBS_LATENCY_BUCKETS:
                acc += h["buckets"][b]
                lines.append(f'event_e2e_latency_seconds_bucket{{event_type="{et}",consumer="{cons}",le="{b}"}} {acc}')
            lines.append(f'event_e2e_latency_seconds_bucket{{event_type="{et}",consumer="{cons}",le="+Inf"}} {h["count"]}')
            lines.append(f'event_e2e_latency_seconds_sum{{event_type="{et}",consumer="{cons}"}} {round(h["sum"], 5)}')
            lines.append(f'event_e2e_latency_seconds_count{{event_type="{et}",consumer="{cons}"}} {h["count"]}')

        # 3. Consumer Health
        lines.append("# HELP consumer_processed_total Total count of successfully handled stream items per consumer.")
        lines.append("# TYPE consumer_processed_total counter")
        lines.append("# HELP consumer_backlog_total Number of unread stream messages pending execution per consumer.")
        lines.append("# TYPE consumer_backlog_total gauge")
        lines.append("# HELP consumer_status Status flag (1=Healthy/Processing, 0=Stalled/Degraded/Stopped).")
        lines.append("# TYPE consumer_status gauge")
        for c_name, data in self.consumers.items():
            lines.append(f'consumer_processed_total{{consumer="{c_name}"}} {data["processed"]}')
            lines.append(f'consumer_failed_total{{consumer="{c_name}"}} {data["failed"]}')
            lines.append(f'consumer_retries_total{{consumer="{c_name}"}} {data["retries"]}')
            lines.append(f'consumer_backlog_total{{consumer="{c_name}"}} {data["backlog"]}')
            status_val = 1 if data["status"] in (ConsumerStatusEnum.IDLE, ConsumerStatusEnum.PROCESSING) else 0
            lines.append(f'consumer_status{{consumer="{c_name}",state="{data["status"].value}"}} {status_val}')

        # 4. WebSocket Observability
        lines.append("# HELP ws_active_connections Current active WebSocket connections to SOC/SIEM clients.")
        lines.append("# TYPE ws_active_connections gauge")
        lines.append(f"ws_active_connections {self.ws_active_connections}")

        lines.append("# HELP ws_connections_opened_total Total number of WebSocket sessions initiated.")
        lines.append("# TYPE ws_connections_opened_total counter")
        lines.append(f"ws_connections_opened_total {self.ws_connections_opened_total}")

        lines.append("# HELP ws_connections_closed_total Total number of WebSocket sessions terminated.")
        lines.append("# TYPE ws_connections_closed_total counter")
        lines.append(f"ws_connections_closed_total {self.ws_connections_closed_total}")

        lines.append("# HELP ws_client_state_count Current count of connected clients in distinct operational states.")
        lines.append("# TYPE ws_client_state_count gauge")
        for st, c_cnt in self.ws_client_states.items():
            lines.append(f'ws_client_state_count{{state="{st.value}"}} {c_cnt}')

        lines.append("# HELP ws_messages_sent_total Total broadcasts dispatched over WebSockets.")
        lines.append("# TYPE ws_messages_sent_total counter")
        lines.append(f"ws_messages_sent_total {self.ws_messages_sent_total}")

        lines.append("# HELP ws_broadcast_latency_seconds Latency from Redis publication to WebSocket transmission.")
        lines.append("# TYPE ws_broadcast_latency_seconds histogram")
        for topic, h in self.ws_broadcast_latency_hist.items():
            acc = 0
            for b in OBS_LATENCY_BUCKETS:
                acc += h["buckets"][b]
                lines.append(f'ws_broadcast_latency_seconds_bucket{{topic="{topic}",le="{b}"}} {acc}')
            lines.append(f'ws_broadcast_latency_seconds_bucket{{topic="{topic}",le="+Inf"}} {h["count"]}')
            lines.append(f'ws_broadcast_latency_seconds_sum{{topic="{topic}"}} {round(h["sum"], 5)}')
            lines.append(f'ws_broadcast_latency_seconds_count{{topic="{topic}"}} {h["count"]}')

        return "\n".join(lines) + "\n"

event_ws_observability = EventAndWebSocketObservability()