import sys
import time
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.observability.system_resource_observability import (
    sys_resource_observability, DBHealthStatus
)

async def run_day201_suite():
    print("=" * 80)
    print("  WEEK 29 - DAY 201: POSTGRESQL, API INFRASTRUCTURE & SYSTEM RESOURCE MONITORING")
    print("================================================================================\n")

    # 1. PostgreSQL Latency Decomposition (Raw Query vs Repo E2E)
    print("[1/8] Testing Database Latency Decomposition (Raw Query vs. API/Repo Path)...")
    # Simulate 5 standard queries and 1 slow query (>100ms)
    for _ in range(5):
        sys_resource_observability.record_query(raw_duration_sec=0.008, repo_duration_sec=0.015, success=True)
    # Slow query
    sys_resource_observability.record_query(raw_duration_sec=0.125, repo_duration_sec=0.142, success=True)
    # Failed query
    sys_resource_observability.record_query(raw_duration_sec=0.005, repo_duration_sec=0.007, success=False)

    assert sys_resource_observability.db_queries_total == 7
    assert sys_resource_observability.db_query_errors_total == 1
    assert sys_resource_observability.db_slow_queries_total == 1
    assert sys_resource_observability.db_repo_e2e_latency_hist["sum"] > sys_resource_observability.db_raw_query_latency_hist["sum"]
    print(f"    Raw Query Latency Sum: {sys_resource_observability.db_raw_query_latency_hist['sum']*1000:.2f}ms")
    print(f"    Repo E2E Latency Sum:  {sys_resource_observability.db_repo_e2e_latency_hist['sum']*1000:.2f}ms")
    print("    [PASS] Database query vs. repository access decomposition verified.")

    # 2. Transaction & Connection Pool Telemetry
    print("\n[2/8] Testing Transaction Life-Cycle & Pool Utilization...")
    sys_resource_observability.record_transaction(duration_sec=0.035, success=True)
    sys_resource_observability.record_transaction(duration_sec=0.010, success=False)
    sys_resource_observability.update_pool_status(active=4, idle=16, max_size=20)

    assert sys_resource_observability.db_transactions_total == 2
    assert sys_resource_observability.db_transaction_failures_total == 1
    assert sys_resource_observability.db_pool_active == 4
    assert sys_resource_observability.db_pool_idle == 16
    assert sys_resource_observability.db_connections_total == 20
    print(f"    DB Pool: Active={sys_resource_observability.db_pool_active} | Idle={sys_resource_observability.db_pool_idle} | Max={sys_resource_observability.db_pool_max_size}")
    print("    [PASS] Transactions and pool metrics tracked accurately.")

    # 3. Dynamic PostgreSQL Health State Evaluation
    print("\n[3/8] Testing Dynamic Database Health State Transitions...")
    # Reset query error counter for clear baseline evaluation
    sys_resource_observability.db_query_errors_total = 0
    sys_resource_observability.update_pool_status(active=3, idle=17, max_size=20)
    sys_resource_observability._evaluate_db_health()
    assert sys_resource_observability.db_health_state == DBHealthStatus.HEALTHY
    print(f"    Baseline State: State={sys_resource_observability.db_health_state.value} | Msg={sys_resource_observability.db_health_message}")

    # Trigger Degraded by pool exhaustion
    sys_resource_observability.update_pool_status(active=19, idle=1, max_size=20)  # 95% utilization
    sys_resource_observability._evaluate_db_health()
    assert sys_resource_observability.db_health_state == DBHealthStatus.DEGRADED
    print(f"    Pool Exhaustion Trigger: State={sys_resource_observability.db_health_state.value} | Msg={sys_resource_observability.db_health_message}")

    # Trigger Unavailable by disconnected socket
    sys_resource_observability.set_db_connectivity(connected=False, error_msg="Connection refused: 5432")
    assert sys_resource_observability.db_health_state == DBHealthStatus.UNAVAILABLE
    print(f"    Socket Disconnect Trigger: State={sys_resource_observability.db_health_state.value} | Msg={sys_resource_observability.db_health_message}")

    # Recover to Healthy
    sys_resource_observability.set_db_connectivity(connected=True)
    sys_resource_observability.update_pool_status(active=3, idle=17, max_size=20)
    sys_resource_observability._evaluate_db_health()
    assert sys_resource_observability.db_health_state == DBHealthStatus.HEALTHY
    print("    [PASS] Database dynamic health states verified.")

    # 4. API Infrastructure Error Stratification
    print("\n[4/8] Auditing API Infrastructure Error Stratification (4xx vs. 5xx vs. Timeout)...")
    sys_resource_observability.record_api_error(status_code=404)
    sys_resource_observability.record_api_error(status_code=403)
    sys_resource_observability.record_api_error(status_code=500)
    sys_resource_observability.record_api_error(status_code=503)
    sys_resource_observability.record_api_error(status_code=504, is_timeout=True)

    assert sys_resource_observability.api_4xx_errors_total == 2
    assert sys_resource_observability.api_5xx_errors_total == 3
    assert sys_resource_observability.api_timeouts_total == 1
    print(f"    API Errors: 4xx={sys_resource_observability.api_4xx_errors_total} | 5xx={sys_resource_observability.api_5xx_errors_total} | Timeouts={sys_resource_observability.api_timeouts_total}")
    print("    [PASS] Error stratification verified.")

    # 5. Host & Process Memory Introspection
    print("\n[5/8] Introspecting System Memory & Process RSS...")
    sys_resource_observability.sample_system_resources()
    total_gb = sys_resource_observability.host_memory_total_bytes / (1024**3)
    used_gb = sys_resource_observability.host_memory_used_bytes / (1024**3)
    avail_gb = sys_resource_observability.host_memory_available_bytes / (1024**3)
    worker_mb = sys_resource_observability.worker_memory_rss_bytes / (1024**2)

    print(f"    Host Total Memory:     {total_gb:.2f} GB")
    print(f"    Host Used Memory:      {used_gb:.2f} GB ({sys_resource_observability.host_memory_percent:.1f}%)")
    print(f"    Host Available Memory: {avail_gb:.2f} GB")
    print(f"    Worker Process RSS:    {worker_mb:.2f} MB")
    assert sys_resource_observability.host_memory_total_bytes > 0
    assert sys_resource_observability.worker_memory_rss_bytes > 0
    print("    [PASS] OS memory introspection successful.")

    # 6. Worker Task Queue Telemetry
    print("\n[6/8] Auditing Background Worker Telemetry & Queue Latencies...")
    sys_resource_observability.update_worker_queue(depth=280, active_workers=4)
    sys_resource_observability.record_worker_job(duration_sec=0.045, success=True)
    sys_resource_observability.record_worker_job(duration_sec=0.080, success=False, retried=True)

    assert sys_resource_observability.active_workers == 4
    assert sys_resource_observability.worker_queue_depth == 280
    assert sys_resource_observability.worker_jobs_completed_total == 1
    assert sys_resource_observability.worker_failures_total == 1
    assert sys_resource_observability.worker_job_retries_total == 1
    print(f"    Active Workers: {sys_resource_observability.active_workers} | Queue Depth: {sys_resource_observability.worker_queue_depth}")
    print("    [PASS] Worker execution telemetry verified.")

    # 7. System Resource Cascade Correlation
    print("\n[7/8] Testing System Resource Correlation Cascade...")
    # Baseline nominal
    sys_resource_observability.host_cpu_percent = 25.0
    sys_resource_observability.host_memory_percent = 45.0
    sys_resource_observability.worker_queue_depth = 50
    nominal_cascade = sys_resource_observability.evaluate_resource_cascade()
    assert nominal_cascade["worker_impact"] == "NORMAL"
    assert nominal_cascade["expected_throughput"] == "NOMINAL"

    # Inject severe resource pressure
    sys_resource_observability.host_cpu_percent = 92.0
    sys_resource_observability.host_memory_percent = 94.0
    sys_resource_observability.worker_queue_depth = 6200
    severe_cascade = sys_resource_observability.evaluate_resource_cascade()
    assert severe_cascade["worker_impact"] == "SEVERE_THROTTLING"
    assert severe_cascade["expected_throughput"] == "CRITICAL_DROP"
    assert severe_cascade["backlog_risk"] == "CRITICAL_ACCUMULATION"
    assert severe_cascade["ws_latency_risk"] == "HIGH_LATENCY_SPIKE"

    print(f"    Cascade Model: {severe_cascade['correlation_chain']}")
    print(f"    Impact Assessment: Worker={severe_cascade['worker_impact']} | Throughput={severe_cascade['expected_throughput']} | WS Risk={severe_cascade['ws_latency_risk']}")
    print("    [PASS] Resource correlation cascade verified.")

    # 8. Prometheus Exposition Formatting
    print("\n[8/8] Rendering Prometheus OpenMetrics Exposition...")
    rendered = sys_resource_observability.render_system_exposition()
    assert "# TYPE db_health gauge" in rendered
    assert "# TYPE db_slow_queries_total counter" in rendered
    assert "# TYPE db_query_latency_seconds histogram" in rendered
    assert "# TYPE db_repo_e2e_latency_seconds histogram" in rendered
    assert "# TYPE api_client_errors_total counter" in rendered
    assert "# TYPE host_memory_used_bytes gauge" in rendered
    assert "# TYPE worker_queue_depth gauge" in rendered
    print("    Sample Exposition Lines:\n    " + "\n    ".join(rendered.splitlines()[:6]))
    print("    [PASS] Prometheus exposition format validated.")

    print("\n" + "=" * 80)
    print("   ALL DAY 201 DATABASE & SYSTEM RESOURCE MONITORING TESTS COMPLETED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day201_suite())