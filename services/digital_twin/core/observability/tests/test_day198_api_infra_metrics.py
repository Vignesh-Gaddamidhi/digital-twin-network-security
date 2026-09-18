import sys
import time
import asyncio
from pathlib import Path
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.observability.prometheus_metrics import platform_metrics
from services.digital_twin.core.observability.infra_metrics import (
    PrometheusMiddleware, infra_metrics
)

async def run_day198_suite():
    print("=" * 80)
    print("       WEEK 29 - DAY 198: DETAILED API & INFRASTRUCTURE METRIC INSTRUMENTATION")
    print("================================================================================\n")

    # 1. Automated ASGI Middleware Intercept Simulation
    print("[1/6] Testing Automated ASGI Prometheus Middleware Intercept...")
    
    # Mock ASGI App & Scope
    async def sample_app(scope, receive, send):
        pass

    middleware = PrometheusMiddleware(sample_app, service_name="twin_api")

    async def mock_call_next_success(req: Request) -> Response:
        await asyncio.sleep(0.015)
        return JSONResponse({"status": "ok"}, status_code=200)

    async def mock_call_next_error(req: Request) -> Response:
        await asyncio.sleep(0.005)
        return JSONResponse({"detail": "Asset not found"}, status_code=404)

    # Dispatch mock HTTP requests
    scope_success = {
        "type": "http", "method": "GET", "path": "/api/v1/devices/DEV-0099",
        "headers": [], "query_string": b""
    }
    req_success = Request(scope_success)
    await middleware.dispatch(req_success, mock_call_next_success)

    scope_err = {
        "type": "http", "method": "GET", "path": "/api/v1/devices/DEV-NOTFOUND",
        "headers": [], "query_string": b""
    }
    req_err = Request(scope_err)
    await middleware.dispatch(req_err, mock_call_next_error)

    # Verify counters recorded under normalized route
    norm_key_200 = ("GET", "/api/v1/devices/{id}", 200, "twin_api")
    norm_key_404 = ("GET", "/api/v1/devices/{id}", 404, "twin_api")
    
    assert norm_key_200 in platform_metrics.requests_total
    assert norm_key_404 in platform_metrics.requests_total
    assert norm_key_404 in platform_metrics.errors_total
    print("    [PASS] Automated middleware intercepted requests, classified status codes, and updated metric registry.")

    # 2. Anti-Cardinality Route Verification Under Middleware
    print("\n[2/6] Auditing Middleware Cardinality Bounds Under Dynamic Param Load...")
    test_ids = [f"DEV-{i:04d}" for i in range(100)]
    for d_id in test_ids:
        s = {"type": "http", "method": "GET", "path": f"/api/v1/devices/{d_id}", "headers": [], "query_string": b""}
        r = Request(s)
        await middleware.dispatch(r, mock_call_next_success)

    # Ensure all 100 requests grouped into the SINGLE normalized key
    total_samples = platform_metrics.requests_total[norm_key_200]
    assert total_samples >= 101, f"Expected >= 101 samples grouped into single key, got {total_samples}"
    
    # Confirm no high-cardinality leak in dictionary keys
    individual_leaks = [k for k in platform_metrics.requests_total.keys() if "DEV-" in k[1]]
    assert len(individual_leaks) == 0, f"Cardinality leak detected: {individual_leaks}"
    print(f"    Consolidated {len(test_ids)} dynamic device requests into single template: '/api/v1/devices/{{id}}'")
    print("    [PASS] Zero cardinality leakage detected.")

    # 3. Database Connection Pool Metrics
    print("\n[3/6] Auditing Database Connection Pool Instrumentation...")
    infra_metrics.db_pool_active = 3
    infra_metrics.db_pool_idle = 7
    infra_metrics.db_pool_max_size = 20
    
    # Record synthetic query latencies
    infra_metrics.record_db_query(0.008)  # 8ms
    infra_metrics.record_db_query(0.042)  # 42ms
    infra_metrics.record_db_query(0.120)  # 120ms
    
    assert infra_metrics.db_query_duration_hist["count"] == 3
    assert infra_metrics.db_query_duration_hist["buckets"][0.01] >= 1
    assert infra_metrics.db_query_duration_hist["buckets"][0.05] >= 2
    assert infra_metrics.db_query_duration_hist["buckets"][0.25] >= 3
    print(f"    DB Pool State: Active={infra_metrics.db_pool_active} | Idle={infra_metrics.db_pool_idle} | Max={infra_metrics.db_pool_max_size}")
    print("    [PASS] Database pool gauges and latency distribution accurately tracked.")

    # 4. Redis Stream Depth & Cache Hit Ratio Accounting
    print("\n[4/6] Auditing Redis Metrics & Cache Hit/Miss Efficiency...")
    infra_metrics.redis_connected_clients = 14
    infra_metrics.redis_used_memory_bytes = 48500000  # ~48.5 MB
    infra_metrics.redis_stream_lengths = {"telemetry": 1240, "simulation": 85, "alerts": 12}
    
    # Track 80 hits, 20 misses
    for _ in range(80):
        infra_metrics.record_cache_lookup(hit=True)
    for _ in range(20):
        infra_metrics.record_cache_lookup(hit=False)

    hit_ratio = infra_metrics.redis_cache_hits / (infra_metrics.redis_cache_hits + infra_metrics.redis_cache_misses)
    print(f"    Cache Hit Ratio: {hit_ratio * 100:.1f}% (Hits={infra_metrics.redis_cache_hits}, Misses={infra_metrics.redis_cache_misses})")
    assert hit_ratio == 0.80
    assert infra_metrics.redis_stream_lengths["telemetry"] == 1240
    print("    [PASS] Redis stream buffer depths and cache accounting verified.")

    # 5. Host Runtime & Process Telemetry
    print("\n[5/6] Auditing Host Runtime Process Metrics...")
    proc_metrics = infra_metrics.collect_process_metrics()
    print(f"    Process CPU: {proc_metrics['process_cpu_percent']}%")
    print(f"    Process RSS Memory: {proc_metrics['process_memory_rss_bytes'] / (1024*1024):.2f} MB")
    print(f"    Active Threads: {int(proc_metrics['process_threads_count'])}")
    assert proc_metrics["process_memory_rss_bytes"] > 0
    assert proc_metrics["process_threads_count"] >= 1
    print("    [PASS] Process telemetry collected successfully via OS kernel hooks.")

    # 6. Combined Prometheus Exposition Rendering
    print("\n[6/6] Rendering Combined Platform & Infrastructure OpenMetrics Exposition...")
    api_expo = platform_metrics.render_prometheus_exposition()
    infra_expo = infra_metrics.render_infra_exposition()
    combined_expo = api_expo + infra_expo

    assert "# TYPE db_pool_active gauge" in combined_expo
    assert "db_pool_active 3" in combined_expo
    assert "db_pool_idle 7" in combined_expo
    assert "# TYPE redis_connected_clients gauge" in combined_expo
    assert "redis_connected_clients 14" in combined_expo
    assert 'redis_stream_length{stream="telemetry"} 1240' in combined_expo
    assert "redis_cache_hits_total 80" in combined_expo
    assert "process_memory_rss_bytes" in combined_expo
    print("    Sample Exposition Block:\n    " + "\n    ".join(infra_expo.splitlines()[:6]))
    print("    [PASS] Unified Prometheus format renders all infrastructure indicators cleanly.")

    print("\n" + "=" * 80)
    print("       ALL DAY 198 API & INFRASTRUCTURE METRIC TESTS COMPLETED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day198_suite())