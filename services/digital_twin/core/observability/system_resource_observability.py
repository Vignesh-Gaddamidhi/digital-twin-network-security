import os
import sys
import time
import ctypes
import threading
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple

class DBHealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"

SYS_LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

class SystemResourceObservability:
    """
    Monitors PostgreSQL persistence health, database transaction latency,
    host & worker memory/CPU utilization, and cross-subsystem resource correlation.
    """
    def __init__(self):
        # 1. PostgreSQL Persistence Metrics
        self.db_health_state: DBHealthStatus = DBHealthStatus.HEALTHY
        self.db_health_message: str = "Connected and operational"
        self.db_connections_total: int = 0
        self.db_pool_active: int = 0
        self.db_pool_idle: int = 10
        self.db_pool_max_size: int = 20
        self.db_queries_total: int = 0
        self.db_query_errors_total: int = 0
        self.db_transactions_total: int = 0
        self.db_transaction_failures_total: int = 0
        self.db_slow_queries_total: int = 0  # Queries > 100ms
        
        # Histograms for query latency and repository round-trip:
        self.db_raw_query_latency_hist: Dict[str, Any] = {
            "buckets": {b: 0 for b in SYS_LATENCY_BUCKETS}, "sum": 0.0, "count": 0, "samples": []
        }
        self.db_repo_e2e_latency_hist: Dict[str, Any] = {
            "buckets": {b: 0 for b in SYS_LATENCY_BUCKETS}, "sum": 0.0, "count": 0, "samples": []
        }
        self.db_tx_latency_hist: Dict[str, Any] = {
            "buckets": {b: 0 for b in SYS_LATENCY_BUCKETS}, "sum": 0.0, "count": 0, "samples": []
        }

        # 2. API Infrastructure Errors
        self.api_4xx_errors_total: int = 0
        self.api_5xx_errors_total: int = 0
        self.api_timeouts_total: int = 0

        # 3. Host and Process Resources
        self.host_cpu_percent: float = 0.0
        self.process_cpu_percent: float = 0.0
        self.host_memory_total_bytes: float = 16.0 * (1024**3)
        self.host_memory_used_bytes: float = 8.0 * (1024**3)
        self.host_memory_available_bytes: float = 8.0 * (1024**3)
        self.host_memory_percent: float = 50.0
        self.worker_memory_rss_bytes: float = 150.0 * (1024**2)
        self.redis_memory_bytes: float = 45.0 * (1024**2)

        # 4. Worker Task Queue Telemetry
        self.active_workers: int = 4
        self.worker_failures_total: int = 0
        self.worker_jobs_completed_total: int = 0
        self.worker_job_retries_total: int = 0
        self.worker_queue_depth: int = 0
        self.worker_job_latency_hist: Dict[str, Any] = {
            "buckets": {b: 0 for b in SYS_LATENCY_BUCKETS}, "sum": 0.0, "count": 0, "samples": []
        }

    # ------------------ POSTGRESQL MONITORING ------------------

    def record_query(self, raw_duration_sec: float, repo_duration_sec: float, success: bool = True):
        self.db_queries_total += 1
        if not success:
            self.db_query_errors_total += 1
        if raw_duration_sec > 0.100:
            self.db_slow_queries_total += 1

        self._add_to_hist(self.db_raw_query_latency_hist, raw_duration_sec)
        self._add_to_hist(self.db_repo_e2e_latency_hist, repo_duration_sec)
        self._evaluate_db_health()

    def record_transaction(self, duration_sec: float, success: bool = True):
        self.db_transactions_total += 1
        if not success:
            self.db_transaction_failures_total += 1
        self._add_to_hist(self.db_tx_latency_hist, duration_sec)

    def update_pool_status(self, active: int, idle: int, max_size: int):
        self.db_pool_active = max(0, active)
        self.db_pool_idle = max(0, idle)
        self.db_pool_max_size = max(1, max_size)
        self.db_connections_total = self.db_pool_active + self.db_pool_idle

    def set_db_connectivity(self, connected: bool, error_msg: str = ""):
        if not connected:
            self.db_health_state = DBHealthStatus.UNAVAILABLE
            self.db_health_message = error_msg or "Failed to connect to PostgreSQL socket"
        else:
            self.db_health_state = DBHealthStatus.HEALTHY
            self.db_health_message = "Connected and responsive"
            self._evaluate_db_health()

    def _evaluate_db_health(self):
        if self.db_health_state == DBHealthStatus.UNAVAILABLE:
            return
        
        # Determine health based on query errors and pool exhaustion
        err_rate = self.db_query_errors_total / max(1, self.db_queries_total)
        pool_util = self.db_pool_active / max(1, self.db_pool_max_size)

        if err_rate > 0.25:
            self.db_health_state = DBHealthStatus.ERROR
            self.db_health_message = f"High SQL error rate: {err_rate*100:.1f}%"
        elif pool_util >= 0.90 or err_rate > 0.05 or self.db_slow_queries_total > 50:
            self.db_health_state = DBHealthStatus.DEGRADED
            self.db_health_message = f"Degraded: Pool utilization {pool_util*100:.1f}%, slow queries {self.db_slow_queries_total}"
        else:
            self.db_health_state = DBHealthStatus.HEALTHY
            self.db_health_message = "PostgreSQL responsive within SLA"

    # ------------------ API INFRASTRUCTURE ERRORS ------------------

    def record_api_error(self, status_code: int, is_timeout: bool = False):
        if is_timeout or status_code in (408, 504):
            self.api_timeouts_total += 1
        if 400 <= status_code < 500:
            self.api_4xx_errors_total += 1
        elif status_code >= 500:
            self.api_5xx_errors_total += 1

    # ------------------ SYSTEM & MACHINE RESOURCES ------------------

    def sample_system_resources(self):
        """Introspect host and process memory/CPU using platform-native APIs."""
        if sys.platform == "win32":
            try:
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ('dwLength', ctypes.c_ulong),
                        ('dwMemoryLoad', ctypes.c_ulong),
                        ('ullTotalPhys', ctypes.c_ulonglong),
                        ('ullAvailPhys', ctypes.c_ulonglong),
                        ('ullTotalPageFile', ctypes.c_ulonglong),
                        ('ullAvailPageFile', ctypes.c_ulonglong),
                        ('ullTotalVirtual', ctypes.c_ulonglong),
                        ('ullAvailVirtual', ctypes.c_ulonglong),
                        ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                    self.host_memory_total_bytes = float(stat.ullTotalPhys)
                    self.host_memory_available_bytes = float(stat.ullAvailPhys)
                    self.host_memory_used_bytes = float(stat.ullTotalPhys - stat.ullAvailPhys)
                    self.host_memory_percent = float(stat.dwMemoryLoad)
            except Exception:
                pass

        if sys.platform == "win32":
            try:
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
                    self.worker_memory_rss_bytes = float(counters.WorkingSetSize)
            except Exception:
                pass

    # ------------------ WORKER MONITORING ------------------

    def record_worker_job(self, duration_sec: float, success: bool = True, retried: bool = False):
        if success:
            self.worker_jobs_completed_total += 1
        else:
            self.worker_failures_total += 1
        if retried:
            self.worker_job_retries_total += 1
        self._add_to_hist(self.worker_job_latency_hist, duration_sec)

    def update_worker_queue(self, depth: int, active_workers: int = 4):
        self.worker_queue_depth = max(0, depth)
        self.active_workers = max(0, active_workers)

    # ------------------ SYSTEM CORRELATION CASCADE ------------------

    def evaluate_resource_cascade(self) -> Dict[str, Any]:
        """
        Calculates the correlated health degradation chain:
        CPU/Mem Pressure -> Worker Slowdown -> Throughput Drop -> Queue Backlog -> WS Latency Spike
        """
        mem_pressure = self.host_memory_percent / 100.0
        cpu_pressure = min(1.0, self.host_cpu_percent / 100.0)
        composite_pressure = max(mem_pressure, cpu_pressure)

        worker_impact = "NORMAL"
        expected_throughput = "NOMINAL"
        backlog_risk = "LOW"
        ws_latency_risk = "LOW"

        if composite_pressure > 0.85 or self.worker_queue_depth > 5000:
            worker_impact = "SEVERE_THROTTLING"
            expected_throughput = "CRITICAL_DROP"
            backlog_risk = "CRITICAL_ACCUMULATION"
            ws_latency_risk = "HIGH_LATENCY_SPIKE"
        elif composite_pressure > 0.70 or self.worker_queue_depth > 1000:
            worker_impact = "DEGRADED_EXECUTION"
            expected_throughput = "REDUCED_RATE"
            backlog_risk = "ELEVATED_LAG"
            ws_latency_risk = "MODERATE_DELAY"

        return {
            "composite_pressure_score": round(composite_pressure, 2),
            "worker_impact": worker_impact,
            "expected_throughput": expected_throughput,
            "backlog_risk": backlog_risk,
            "ws_latency_risk": ws_latency_risk,
            "correlation_chain": "CPU/Mem Pressure -> Worker Slowdown -> Event Drop -> Queue Backlog -> WS Latency Spike"
        }

    # ------------------ HISTOGRAM HELPER ------------------

    def _add_to_hist(self, target: Dict[str, Any], val: float):
        target["sum"] += val
        target["count"] += 1
        target["samples"].append(val)
        if len(target["samples"]) > 1000:
            target["samples"].pop(0)
        for b in SYS_LATENCY_BUCKETS:
            if val <= b:
                target["buckets"][b] += 1

    # ------------------ PROMETHEUS EXPOSITION ------------------

    def render_system_exposition(self) -> str:
        lines = []

        # 1. PostgreSQL Metrics
        lines.append("# HELP db_health Subsystem health indicator (1=Healthy, 0=Degraded/Down).")
        lines.append("# TYPE db_health gauge")
        score = 1 if self.db_health_state == DBHealthStatus.HEALTHY else 0
        lines.append(f'db_health{{status="{self.db_health_state.value}"}} {score}')

        lines.append("# HELP db_queries_total Total executed database queries.")
        lines.append("# TYPE db_queries_total counter")
        lines.append(f"db_queries_total {self.db_queries_total}")

        lines.append("# HELP db_query_errors_total Total failed SQL query executions.")
        lines.append("# TYPE db_query_errors_total counter")
        lines.append(f"db_query_errors_total {self.db_query_errors_total}")

        lines.append("# HELP db_slow_queries_total Queries exceeding 100ms SLA threshold.")
        lines.append("# TYPE db_slow_queries_total counter")
        lines.append(f"db_slow_queries_total {self.db_slow_queries_total}")

        lines.append("# HELP db_transactions_total Total transactions initiated.")
        lines.append("# TYPE db_transactions_total counter")
        lines.append(f"db_transactions_total {self.db_transactions_total}")

        lines.append("# HELP db_transaction_failures_total Total transactions rolled back.")
        lines.append("# TYPE db_transaction_failures_total counter")
        lines.append(f"db_transaction_failures_total {self.db_transaction_failures_total}")

        lines.append("# HELP db_pool_active Current database pool connections in use.")
        lines.append("# TYPE db_pool_active gauge")
        lines.append(f"db_pool_active {self.db_pool_active}")

        lines.append("# HELP db_pool_idle Available idle database connections.")
        lines.append("# TYPE db_pool_idle gauge")
        lines.append(f"db_pool_idle {self.db_pool_idle}")

        # Latency histograms
        lines.append("# HELP db_query_latency_seconds PostgreSQL raw query duration.")
        lines.append("# TYPE db_query_latency_seconds histogram")
        acc = 0
        for b in SYS_LATENCY_BUCKETS:
            acc += self.db_raw_query_latency_hist["buckets"][b]
            lines.append(f'db_query_latency_seconds_bucket{{le="{b}"}} {acc}')
        lines.append(f'db_query_latency_seconds_bucket{{le="+Inf"}} {self.db_raw_query_latency_hist["count"]}')
        lines.append(f'db_query_latency_seconds_sum {round(self.db_raw_query_latency_hist["sum"], 5)}')
        lines.append(f'db_query_latency_seconds_count {self.db_raw_query_latency_hist["count"]}')

        lines.append("# HELP db_repo_e2e_latency_seconds Latency of API to repository to DB call.")
        lines.append("# TYPE db_repo_e2e_latency_seconds histogram")
        acc_repo = 0
        for b in SYS_LATENCY_BUCKETS:
            acc_repo += self.db_repo_e2e_latency_hist["buckets"][b]
            lines.append(f'db_repo_e2e_latency_seconds_bucket{{le="{b}"}} {acc_repo}')
        lines.append(f'db_repo_e2e_latency_seconds_bucket{{le="+Inf"}} {self.db_repo_e2e_latency_hist["count"]}')
        lines.append(f'db_repo_e2e_latency_seconds_sum {round(self.db_repo_e2e_latency_hist["sum"], 5)}')
        lines.append(f'db_repo_e2e_latency_seconds_count {self.db_repo_e2e_latency_hist["count"]}')

        # 2. API Infrastructure Errors
        lines.append("# HELP api_client_errors_total Total 4xx responses emitted.")
        lines.append("# TYPE api_client_errors_total counter")
        lines.append(f"api_client_errors_total {self.api_4xx_errors_total}")

        lines.append("# HELP api_server_errors_total Total 5xx responses emitted.")
        lines.append("# TYPE api_server_errors_total counter")
        lines.append(f"api_server_errors_total {self.api_5xx_errors_total}")

        lines.append("# HELP api_timeouts_total Total request timeouts recorded.")
        lines.append("# TYPE api_timeouts_total counter")
        lines.append(f"api_timeouts_total {self.api_timeouts_total}")

        # 3. System Resources
        lines.append("# HELP host_cpu_percent Total system CPU utilization percentage.")
        lines.append("# TYPE host_cpu_percent gauge")
        lines.append(f"host_cpu_percent {self.host_cpu_percent}")

        lines.append("# HELP host_memory_percent System physical memory utilization percentage.")
        lines.append("# TYPE host_memory_percent gauge")
        lines.append(f"host_memory_percent {self.host_memory_percent}")

        lines.append("# HELP host_memory_used_bytes Total system physical memory consumed.")
        lines.append("# TYPE host_memory_used_bytes gauge")
        lines.append(f"host_memory_used_bytes {self.host_memory_used_bytes}")

        lines.append("# HELP host_memory_available_bytes Free/Available physical memory.")
        lines.append("# TYPE host_memory_available_bytes gauge")
        lines.append(f"host_memory_available_bytes {self.host_memory_available_bytes}")

        lines.append("# HELP worker_memory_rss_bytes Resident memory allocated by worker processes.")
        lines.append("# TYPE worker_memory_rss_bytes gauge")
        lines.append(f"worker_memory_rss_bytes {self.worker_memory_rss_bytes}")

        # 4. Worker Monitoring
        lines.append("# HELP active_workers Number of background worker processes executing.")
        lines.append("# TYPE active_workers gauge")
        lines.append(f"active_workers {self.active_workers}")

        lines.append("# HELP worker_queue_depth Pending tasks waiting in worker queue.")
        lines.append("# TYPE worker_queue_depth gauge")
        lines.append(f"worker_queue_depth {self.worker_queue_depth}")

        lines.append("# HELP worker_jobs_completed_total Successfully finished worker jobs.")
        lines.append("# TYPE worker_jobs_completed_total counter")
        lines.append(f"worker_jobs_completed_total {self.worker_jobs_completed_total}")

        lines.append("# HELP worker_failures_total Total failed worker executions.")
        lines.append("# TYPE worker_failures_total counter")
        lines.append(f"worker_failures_total {self.worker_failures_total}")

        return "\n".join(lines) + "\n"

sys_resource_observability = SystemResourceObservability()