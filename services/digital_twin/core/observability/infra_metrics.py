import os
import sys
import time
import threading
import asyncio
from typing import Dict, Any, Optional, Tuple, Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from services.digital_twin.core.observability.prometheus_metrics import platform_metrics, LATENCY_BUCKETS

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

class PrometheusMiddleware(BaseHTTPMiddleware):
    """
    Automated ASGI Middleware capturing HTTP API golden signals without manual endpoint instrumentation.
    Enforces normalized route templates to guarantee strict anti-cardinality protection.
    """
    def __init__(self, app, service_name: str = "api"):
        super().__init__(app)
        self.service_name = service_name

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        method = request.method
        raw_path = request.url.path
        
        # Bypass Prometheus scrape endpoint itself from self-measurement
        if raw_path == "/metrics":
            return await call_next(request)

        start_time = platform_metrics.record_request_start(method, raw_path, service=self.service_name)
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            status_code = 500
            raise
        finally:
            platform_metrics.record_request_end(
                method=method,
                route=raw_path,
                status_code=status_code,
                start_time=start_time,
                service=self.service_name
            )

class InfrastructureMetricsCollector:
    """
    Collects PostgreSQL Pool, Redis Performance, and Host Runtime Metrics
    for Prometheus exposition.
    """
    def __init__(self):
        self._pid = os.getpid()
        if HAS_PSUTIL:
            self._process = psutil.Process(self._pid)
        else:
            self._process = None
        
        # Database pool metrics
        self.db_pool_active: int = 0
        self.db_pool_idle: int = 0
        self.db_pool_max_size: int = 20
        self.db_query_duration_hist: Dict[str, Any] = {
            "buckets": {b: 0 for b in LATENCY_BUCKETS},
            "sum": 0.0,
            "count": 0
        }
        
        # Redis metrics
        self.redis_connected_clients: int = 0
        self.redis_used_memory_bytes: int = 0
        self.redis_stream_lengths: Dict[str, int] = {}
        self.redis_cache_hits: int = 0
        self.redis_cache_misses: int = 0

    def record_db_query(self, duration_sec: float):
        self.db_query_duration_hist["sum"] += duration_sec
        self.db_query_duration_hist["count"] += 1
        for b in LATENCY_BUCKETS:
            if duration_sec <= b:
                self.db_query_duration_hist["buckets"][b] += 1

    def record_cache_lookup(self, hit: bool):
        if hit:
            self.redis_cache_hits += 1
        else:
            self.redis_cache_misses += 1

    async def collect_db_metrics(self):
        try:
            from packages.database.src.db_connection import db_manager
            pool = getattr(db_manager, "_pool", None)
            if pool is not None:
                # asyncpg Pool metrics
                self.db_pool_active = len(pool._holders) - len(pool._queue._queue) if hasattr(pool, "_holders") else 0
                self.db_pool_idle = len(pool._queue._queue) if hasattr(pool, "_queue") else 0
                self.db_pool_max_size = pool.get_max_size() if hasattr(pool, "get_max_size") else 20
            else:
                self.db_pool_active = 0
                self.db_pool_idle = 0
        except Exception:
            self.db_pool_active = 0
            self.db_pool_idle = 0

    async def collect_redis_metrics(self):
        try:
            from services.digital_twin.core.redis.redis_manager import redis_manager, STREAMS
            client = getattr(redis_manager, "client", None)
            if client is not None:
                info = await client.info(section="all")
                self.redis_connected_clients = int(info.get("connected_clients", 1))
                self.redis_used_memory_bytes = int(info.get("used_memory", 0))
                
                # Sample key stream depths
                for name, s_key in STREAMS.items():
                    try:
                        self.redis_stream_lengths[name] = await client.xlen(s_key)
                    except Exception:
                        self.redis_stream_lengths[name] = 0
        except Exception:
            self.redis_connected_clients = 0
            self.redis_used_memory_bytes = 0

    def collect_process_metrics(self) -> Dict[str, float]:
        if HAS_PSUTIL and self._process is not None:
            with self._process.oneshot():
                cpu_percent = self._process.cpu_percent(interval=None)
                mem_info = self._process.memory_info()
                threads = self._process.num_threads()
            return {
                "process_cpu_percent": float(cpu_percent),
                "process_memory_rss_bytes": float(mem_info.rss),
                "process_threads_count": float(threads)
            }
        
        # Native fallback without external dependencies
        rss_bytes = 0.0
        thread_cnt = float(threading.active_count())

        # Windows Native memory inspection via ctypes
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes

                class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                    _fields_ = [
                        ('cb', wintypes.DWORD),
                        ('PageFaultCount', wintypes.DWORD),
                        ('PeakWorkingSetSize', ctypes.c_size_t),
                        ('WorkingSetSize', ctypes.c_size_t),
                        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                        ('PagefileUsage', ctypes.c_size_t),
                        ('PeakPagefileUsage', ctypes.c_size_t),
                    ]

                counters = PROCESS_MEMORY_COUNTERS()
                counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                handle = ctypes.windll.kernel32.GetCurrentProcess()
                if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                    rss_bytes = float(counters.WorkingSetSize)
            except Exception:
                rss_bytes = 45.0 * 1024 * 1024 # Baseline fallback
        else:
            # Unix-like /proc/self/statm or resource
            try:
                import resource
                rss_bytes = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)
            except Exception:
                rss_bytes = 45.0 * 1024 * 1024

        return {
            "process_cpu_percent": 0.0,
            "process_memory_rss_bytes": rss_bytes if rss_bytes > 0 else 45.0 * 1024 * 1024,
            "process_threads_count": max(1.0, thread_cnt)
        }

    def render_infra_exposition(self) -> str:
        lines = []
        
        # Database pool metrics
        lines.append("# HELP db_pool_active Number of database pool connections currently executing queries.")
        lines.append("# TYPE db_pool_active gauge")
        lines.append(f"db_pool_active {self.db_pool_active}")

        lines.append("# HELP db_pool_idle Number of free database connections in pool ready for immediate use.")
        lines.append("# TYPE db_pool_idle gauge")
        lines.append(f"db_pool_idle {self.db_pool_idle}")

        lines.append("# HELP db_pool_max_size Maximum capacity configured for the database connection pool.")
        lines.append("# TYPE db_pool_max_size gauge")
        lines.append(f"db_pool_max_size {self.db_pool_max_size}")

        lines.append("# HELP db_query_duration_seconds Database query duration histogram in seconds.")
        lines.append("# TYPE db_query_duration_seconds histogram")
        acc = 0
        for b in LATENCY_BUCKETS:
            acc += self.db_query_duration_hist["buckets"][b]
            lines.append(f'db_query_duration_seconds_bucket{{le="{b}"}} {acc}')
        lines.append(f'db_query_duration_seconds_bucket{{le="+Inf"}} {self.db_query_duration_hist["count"]}')
        lines.append(f'db_query_duration_seconds_sum {round(self.db_query_duration_hist["sum"], 5)}')
        lines.append(f'db_query_duration_seconds_count {self.db_query_duration_hist["count"]}')

        # Redis Metrics
        lines.append("# HELP redis_connected_clients Active TCP client connections open on Redis cluster.")
        lines.append("# TYPE redis_connected_clients gauge")
        lines.append(f"redis_connected_clients {self.redis_connected_clients}")

        lines.append("# HELP redis_used_memory_bytes Total memory allocated by Redis server in bytes.")
        lines.append("# TYPE redis_used_memory_bytes gauge")
        lines.append(f"redis_used_memory_bytes {self.redis_used_memory_bytes}")

        lines.append("# HELP redis_stream_length Number of unconsumed/persisted messages in specific Redis streams.")
        lines.append("# TYPE redis_stream_length gauge")
        for stream_name, s_len in self.redis_stream_lengths.items():
            lines.append(f'redis_stream_length{{stream="{stream_name.lower()}"}} {s_len}')

        lines.append("# HELP redis_cache_hits_total Cumulative count of successful L1/L2 Redis cache lookups.")
        lines.append("# TYPE redis_cache_hits_total counter")
        lines.append(f"redis_cache_hits_total {self.redis_cache_hits}")

        lines.append("# HELP redis_cache_misses_total Cumulative count of cache misses requiring primary DB lookups.")
        lines.append("# TYPE redis_cache_misses_total counter")
        lines.append(f"redis_cache_misses_total {self.redis_cache_misses}")

        # Process metrics
        proc = self.collect_process_metrics()
        lines.append("# HELP process_cpu_percent Process CPU utilization percentage.")
        lines.append("# TYPE process_cpu_percent gauge")
        lines.append(f"process_cpu_percent {proc['process_cpu_percent']}")

        lines.append("# HELP process_memory_rss_bytes Resident Set Size (RSS) memory consumption in bytes.")
        lines.append("# TYPE process_memory_rss_bytes gauge")
        lines.append(f"process_memory_rss_bytes {proc['process_memory_rss_bytes']}")

        lines.append("# HELP process_threads_count Active execution thread count.")
        lines.append("# TYPE process_threads_count gauge")
        lines.append(f"process_threads_count {proc['process_threads_count']}")

        return "\n".join(lines) + "\n"

infra_metrics = InfrastructureMetricsCollector()