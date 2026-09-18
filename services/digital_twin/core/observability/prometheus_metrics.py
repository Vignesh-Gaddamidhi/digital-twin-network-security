import time
import math
import asyncio
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple

class HealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

class SubsystemEnum(str, Enum):
    API = "api"
    DATABASE = "database"
    REDIS = "redis"
    DIGITAL_TWIN = "digital_twin"
    ML_ENGINE = "ml_engine"
    SIMULATION = "simulation"
    WEBSOCKET = "websocket"
    IDS = "ids"

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

class PrometheusMetricsRegistry:
    def __init__(self):
        self._lock = asyncio.Lock()
        self.requests_total: Dict[Tuple[str, str, int, str], int] = {}
        self.errors_total: Dict[Tuple[str, str, int, str], int] = {}
        self.active_requests: Dict[Tuple[str, str], int] = {}
        
        # Histograms: (method, route, service) -> {bucket: count, "sum": float, "count": int, "observations": list}
        self.duration_histograms: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        
        # Service health mappings
        self.service_health: Dict[SubsystemEnum, Dict[str, Any]] = {
            s: {"state": HealthState.UNKNOWN, "latency_ms": 0.0, "last_check": 0.0, "message": "Initialized"}
            for s in SubsystemEnum
        }

    def normalize_route(self, path: str) -> str:
        """Strip high-cardinality UUIDs/IDs into normalized metric route patterns."""
        parts = path.strip("/").split("/")
        normalized = []
        for p in parts:
            if not p:
                continue
            if p.startswith(("DEV-", "SIM-", "INC-", "ALT-", "USR-")) or len(p) > 24 or p.isnumeric():
                normalized.append("{id}")
            else:
                normalized.append(p)
        return "/" + "/".join(normalized) if normalized else "/"

    def record_request_start(self, method: str, route: str, service: str = "api") -> float:
        norm_route = self.normalize_route(route)
        key = (method.upper(), norm_route)
        self.active_requests[key] = self.active_requests.get(key, 0) + 1
        return time.perf_counter()

    def record_request_end(self, method: str, route: str, status_code: int, start_time: float, service: str = "api"):
        duration = max(0.0001, time.perf_counter() - start_time)
        norm_route = self.normalize_route(route)
        method_str = method.upper()

        # Decrement active requests
        active_key = (method_str, norm_route)
        if active_key in self.active_requests:
            self.active_requests[active_key] = max(0, self.active_requests[active_key] - 1)

        # Increment total counter
        counter_key = (method_str, norm_route, status_code, service)
        self.requests_total[counter_key] = self.requests_total.get(counter_key, 0) + 1

        # Check errors
        if status_code >= 400:
            err_key = (method_str, norm_route, status_code, service)
            self.errors_total[err_key] = self.errors_total.get(err_key, 0) + 1

        # Histogram tracking
        hist_key = (method_str, norm_route, service)
        if hist_key not in self.duration_histograms:
            self.duration_histograms[hist_key] = {
                "buckets": {b: 0 for b in LATENCY_BUCKETS},
                "sum": 0.0,
                "count": 0,
                "samples": []
            }

        hist = self.duration_histograms[hist_key]
        hist["sum"] += duration
        hist["count"] += 1
        hist["samples"].append(duration)
        if len(hist["samples"]) > 1000:
            hist["samples"].pop(0)

        for b in LATENCY_BUCKETS:
            if duration <= b:
                hist["buckets"][b] += 1

    def calculate_quantiles(self, method: str, route: str, service: str = "api") -> Dict[str, float]:
        norm_route = self.normalize_route(route)
        hist_key = (method.upper(), norm_route, service)
        hist = self.duration_histograms.get(hist_key)
        if not hist or not hist["samples"]:
            return {"avg": 0.0, "median": 0.0, "p95": 0.0, "p99": 0.0}

        sorted_s = sorted(hist["samples"])
        n = len(sorted_s)
        
        def get_quantile(q: float) -> float:
            idx = int(math.ceil(q * n)) - 1
            return sorted_s[max(0, min(idx, n - 1))]

        return {
            "avg": round(hist["sum"] / hist["count"], 5),
            "median": round(get_quantile(0.50), 5),
            "p95": round(get_quantile(0.95), 5),
            "p99": round(get_quantile(0.99), 5)
        }

    def update_subsystem_health(self, subsystem: SubsystemEnum, state: HealthState, latency_ms: float = 0.0, message: str = ""):
        self.service_health[subsystem] = {
            "state": state,
            "latency_ms": round(latency_ms, 2),
            "last_check": time.time(),
            "message": message
        }

    def render_prometheus_exposition(self) -> str:
        """Render metrics strictly in Prometheus exposition format for :9090 scrapes."""
        lines = []
        
        # HELP and TYPE definitions
        lines.append("# HELP api_requests_total Total count of processed HTTP API requests.")
        lines.append("# TYPE api_requests_total counter")
        for (m, r, sc, s), cnt in self.requests_total.items():
            lines.append(f'api_requests_total{{method="{m}",route="{r}",status_code="{sc}",service="{s}"}} {cnt}')

        lines.append("# HELP api_errors_total Total count of HTTP API errors encountered.")
        lines.append("# TYPE api_errors_total counter")
        for (m, r, sc, s), cnt in self.errors_total.items():
            lines.append(f'api_errors_total{{method="{m}",route="{r}",status_code="{sc}",service="{s}"}} {cnt}')

        lines.append("# HELP api_active_requests Current number of concurrent in-flight requests.")
        lines.append("# TYPE api_active_requests gauge")
        for (m, r), cnt in self.active_requests.items():
            lines.append(f'api_active_requests{{method="{m}",route="{r}"}} {cnt}')

        lines.append("# HELP api_request_duration_seconds HTTP request execution latency histogram.")
        lines.append("# TYPE api_request_duration_seconds histogram")
        for (m, r, s), hist in self.duration_histograms.items():
            acc = 0
            for b in LATENCY_BUCKETS:
                acc += hist["buckets"][b]
                lines.append(f'api_request_duration_seconds_bucket{{method="{m}",route="{r}",service="{s}",le="{b}"}} {acc}')
            lines.append(f'api_request_duration_seconds_bucket{{method="{m}",route="{r}",service="{s}",le="+Inf"}} {hist["count"]}')
            lines.append(f'api_request_duration_seconds_sum{{method="{m}",route="{r}",service="{s}"}} {round(hist["sum"], 5)}')
            lines.append(f'api_request_duration_seconds_count{{method="{m}",route="{r}",service="{s}"}} {hist["count"]}')

        lines.append("# HELP cybertwin_service_health Subsystem operational health status (1=Healthy, 0=Degraded/Down).")
        lines.append("# TYPE cybertwin_service_health gauge")
        for sub, details in self.service_health.items():
            score = 1 if details["state"] == HealthState.HEALTHY else 0
            lines.append(f'cybertwin_service_health{{service="{sub.value}",state="{details["state"].value}"}} {score}')
            lines.append(f'cybertwin_service_latency_milliseconds{{service="{sub.value}"}} {details["latency_ms"]}')

        return "\n".join(lines) + "\n"

# Singleton platform metrics instance
platform_metrics = PrometheusMetricsRegistry()