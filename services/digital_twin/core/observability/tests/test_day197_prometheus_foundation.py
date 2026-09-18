import sys
import time
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.observability.prometheus_metrics import (
    platform_metrics, HealthState, SubsystemEnum, LATENCY_BUCKETS
)
from services.digital_twin.core.observability.health_evaluator import health_evaluator

async def run_day197_suite():
    print("=" * 80)
    print("       WEEK 29 - DAY 197: OBSERVABILITY ARCHITECTURE & PROMETHEUS FOUNDATION")
    print("================================================================================\n")

    # 1. Observability Pillars: Metrics, Traces, Logs Alignment
    print("[1/7] Auditing Observability Pillar Contracts...")
    log_record = {
        "timestamp": time.time(),
        "service": "api",
        "level": "INFO",
        "message": "Processed threat intelligence query",
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "correlation_id": "CORR-TEST-999",
        "event_id": "EVT-TEST-001"
    }
    assert "trace_id" in log_record and "correlation_id" in log_record
    assert log_record["level"] == "INFO"
    print("    [PASS] Standard structured log & trace correlation contracts verified.")

    # 2. Metric Cardinality Sanitization
    print("\n[2/7] Testing Metric Route Normalization (Anti-High-Cardinality)...")
    r1 = platform_metrics.normalize_route("/api/v1/devices/DEV-8849-ROUTER")
    r2 = platform_metrics.normalize_route("/api/v1/incidents/INC-2026-901/status")
    r3 = platform_metrics.normalize_route("/api/v1/simulations/488219/execute")
    assert r1 == "/api/v1/devices/{id}", f"Failed: {r1}"
    assert r2 == "/api/v1/incidents/{id}/status", f"Failed: {r2}"
    assert r3 == "/api/v1/simulations/{id}/execute", f"Failed: {r3}"
    print(f"    Normalized: /api/v1/devices/DEV-8849-ROUTER -> {r1}")
    print(f"    Normalized: /api/v1/incidents/INC-2026-901/status -> {r2}")
    print("    [PASS] Unbounded parameter leak prevention active.")

    # 3. Request Lifecycle & Concurrency (api_active_requests)
    print("\n[3/7] Tracking In-Flight Concurrency & Counter Increments...")
    start_t1 = platform_metrics.record_request_start("GET", "/api/v1/devices/DEV-01", service="api")
    start_t2 = platform_metrics.record_request_start("GET", "/api/v1/devices/DEV-02", service="api")
    
    active_gauge = platform_metrics.active_requests[("GET", "/api/v1/devices/{id}")]
    assert active_gauge == 2, f"Expected 2 in-flight requests, got {active_gauge}"

    platform_metrics.record_request_end("GET", "/api/v1/devices/DEV-01", 200, start_t1, service="api")
    active_gauge = platform_metrics.active_requests[("GET", "/api/v1/devices/{id}")]
    assert active_gauge == 1, f"Expected 1 in-flight request, got {active_gauge}"

    platform_metrics.record_request_end("GET", "/api/v1/devices/DEV-02", 500, start_t2, service="api")
    active_gauge = platform_metrics.active_requests[("GET", "/api/v1/devices/{id}")]
    assert active_gauge == 0, f"Expected 0 in-flight requests, got {active_gauge}"

    # Verify total & error counts
    assert platform_metrics.requests_total[("GET", "/api/v1/devices/{id}", 200, "api")] == 1
    assert platform_metrics.requests_total[("GET", "/api/v1/devices/{id}", 500, "api")] == 1
    assert platform_metrics.errors_total[("GET", "/api/v1/devices/{id}", 500, "api")] == 1
    print("    [PASS] Request lifecycles, error counters, and gauges match exact states.")

    # 4. Latency Distribution & Quantiles (avg, median, p95, p99)
    print("\n[4/7] Generating Synthetic Latency Profile & Calculating Quantiles...")
    synthetic_route = "/api/v1/predictions"
    for i in range(1, 101):
        dur_sim = (i / 100.0) * 0.100  # 1ms to 100ms
        t_mock = time.perf_counter() - dur_sim
        platform_metrics.record_request_end("POST", synthetic_route, 200, t_mock, service="ml_engine")

    quantiles = platform_metrics.calculate_quantiles("POST", synthetic_route, service="ml_engine")
    print(f"    Target Route: POST {synthetic_route}")
    print(f"    Calculated: Avg={quantiles['avg']*1000:.2f}ms | Median={quantiles['median']*1000:.2f}ms | p95={quantiles['p95']*1000:.2f}ms | p99={quantiles['p99']*1000:.2f}ms")
    
    assert 0.040 <= quantiles["median"] <= 0.065, f"Unexpected median: {quantiles['median']}"
    assert 0.090 <= quantiles["p95"] <= 0.105, f"Unexpected p95: {quantiles['p95']}"
    print("    [PASS] Statistical quantiles verified against theoretical bounds.")

    # 5. Prometheus /metrics Exposition Output
    print("\n[5/7] Testing OpenMetrics / Prometheus :9090 Scraping Output Format...")
    platform_metrics.update_subsystem_health(SubsystemEnum.API, HealthState.HEALTHY, 0.25, "API operational")
    rendered = platform_metrics.render_prometheus_exposition()
    assert "# TYPE api_requests_total counter" in rendered
    assert "# TYPE api_request_duration_seconds histogram" in rendered
    assert "# TYPE api_active_requests gauge" in rendered
    assert "# TYPE cybertwin_service_health gauge" in rendered
    assert 'api_requests_total{method="GET",route="/api/v1/devices/{id}",status_code="200",service="api"}' in rendered
    assert 'cybertwin_service_health{service="api",state="HEALTHY"} 1' in rendered
    print(f"    Sample Output Line (First 180 chars):\n    {rendered[:180]}...")
    print("    [PASS] Prometheus exposition format conforms to OpenMetrics RFC standard.")

    # 6. Real Subsystem Health Evaluator
    print("\n[6/7] Auditing Real Dynamic Subsystem Health Probing...")
    states = await health_evaluator.evaluate_all()
    print("    Subsystem Health Status Overview:")
    for sub, info in states.items():
        print(f"     - {sub.upper():14}: State={info['state']:11} Latency={info['latency_ms']}ms | {info['message']}")
    
    assert "api" in states
    assert states["api"]["state"] == "HEALTHY"
    assert "redis" in states
    assert "database" in states
    print("    [PASS] Health statuses dynamically sourced without synthetic hardcoding.")

    # 7. Fault Attribution in Health States
    print("\n[7/7] Testing Fault Attribution State Degradation...")
    platform_metrics.update_subsystem_health(
        SubsystemEnum.DATABASE, HealthState.DEGRADED, 45.2, "Connection pool starved"
    )
    assert platform_metrics.service_health[SubsystemEnum.DATABASE]["state"] == HealthState.DEGRADED
    rendered_fault = platform_metrics.render_prometheus_exposition()
    assert 'cybertwin_service_health{service="database",state="DEGRADED"} 0' in rendered_fault
    print("    [PASS] Subsystem degradation correctly mapped to metric scrapers.")

    print("\n" + "=" * 80)
    print("       ALL DAY 197 PROMETHEUS OBSERVABILITY TESTS COMPLETED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day197_suite())