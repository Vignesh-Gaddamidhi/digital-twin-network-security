import sys
import time
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.observability.intelligence_observability import (
    intel_observability, MLHealthStatus, SimulationScenarioEnum
)

async def run_day200_suite():
    print("=" * 80)
    print("       WEEK 29 - DAY 200: DIGITAL TWIN, SIMULATION & ML OBSERVABILITY")
    print("================================================================================\n")

    # 1. Digital Twin Metrics & 3-Stage Synchronization Latencies
    print("[1/7] Testing Digital Twin Graph Mutations & Synchronization Pipelines...")
    intel_observability.update_twin_topology_counts(devices=48, connections=112)
    assert intel_observability.devices_tracked == 48
    assert intel_observability.active_connections == 112

    # Record mutations and transitions
    intel_observability.record_twin_update(duration_sec=0.012, success=True)
    intel_observability.record_twin_update(duration_sec=0.005, success=False)
    intel_observability.record_state_transition(success=True)
    intel_observability.record_state_transition(success=False)

    # Record 3 sync paths:
    # 1) Sim -> Redis -> Twin
    intel_observability.record_twin_sync_stage("sim_redis_twin", 0.018)
    # 2) Twin -> Postgres
    intel_observability.record_twin_sync_stage("twin_postgres", 0.024)
    # 3) Twin -> WebSocket -> SOC UI
    intel_observability.record_twin_sync_stage("twin_ws_soc", 0.008)

    assert intel_observability.twin_updates_total == 1
    assert intel_observability.twin_update_failures_total == 1
    assert intel_observability.state_transitions_total == 1
    assert intel_observability.state_transition_failures_total == 1
    assert "sim_redis_twin" in intel_observability.twin_sync_latency_hist
    assert "twin_postgres" in intel_observability.twin_sync_latency_hist
    assert "twin_ws_soc" in intel_observability.twin_sync_latency_hist
    print(f"    Twin Topology: Tracked Devices={intel_observability.devices_tracked} | Active Links={intel_observability.active_connections}")
    print("    [PASS] 3-stage synchronization metrics and twin mutation counters verified.")

    # 2. Simulation Lifecycle & 13 Scenario Coverage
    print("\n[2/7] Testing Simulation Lifecycle & 13 Canonical Scenarios...")
    scenarios = [s.value for s in SimulationScenarioEnum]
    assert len(scenarios) == 13

    for sc in scenarios:
        intel_observability.record_simulation_start(sc)
        intel_observability.record_simulation_event_latency(sc, 0.003)
        intel_observability.record_simulation_end(sc, duration_sec=1.2, events_generated=150, success=True)

    # Fail one DOS_LIKE scenario run
    intel_observability.record_simulation_start("DOS_LIKE")
    intel_observability.record_simulation_end("DOS_LIKE", duration_sec=0.4, events_generated=40, success=False)

    assert intel_observability.simulation_runs_total["DOS_LIKE"] == 2
    assert intel_observability.simulation_runs_completed["DOS_LIKE"] == 1
    assert intel_observability.simulation_runs_failed["DOS_LIKE"] == 1
    assert intel_observability.simulation_runs_active == 0
    print(f"    Audited {len(scenarios)} Scenarios: {', '.join(scenarios[:4])}...")
    print("    [PASS] All 13 scenario taxonomies tracked cleanly.")

    # 3. ML Prediction Latency Quantiles (avg, p50, p95, p99)
    print("\n[3/7] Generating Synthetic Latency Profile & Calculating ML Quantiles...")
    # Inject 100 synthetic inferences across XGBoost v1.0 / BRUTE_FORCE
    target_ver = "v1.0"
    target_cat = "BRUTE_FORCE"
    for i in range(1, 101):
        dur = (i / 100.0) * 0.100  # 1ms to 100ms
        intel_observability.record_ml_prediction(
            model_version=target_ver,
            category=target_cat,
            confidence=0.92,
            duration_sec=dur,
            success=True
        )

    q = intel_observability.calculate_ml_latency_quantiles(target_ver, target_cat)
    print(f"    Target: Model={target_ver} Category={target_cat}")
    print(f"    Quantiles: Avg={q['avg']*1000:.2f}ms | p50={q['p50']*1000:.2f}ms | p95={q['p95']*1000:.2f}ms | p99={q['p99']*1000:.2f}ms")
    assert 0.040 <= q["p50"] <= 0.060
    assert 0.090 <= q["p95"] <= 0.100
    print("    [PASS] Inference latency quantiles match distribution profile.")

    # 4. Prediction Confidence Distribution
    print("\n[4/7] Auditing High vs. Low Confidence Prediction Stratification...")
    # Record 10 low-confidence predictions (< 0.65)
    for _ in range(10):
        intel_observability.record_ml_prediction(
            model_version="v1.0", category="DOS_LIKE", confidence=0.48, duration_sec=0.015, success=True
        )
    # Record 20 high-confidence predictions (>= 0.85)
    for _ in range(20):
        intel_observability.record_ml_prediction(
            model_version="v1.0", category="DOS_LIKE", confidence=0.96, duration_sec=0.015, success=True
        )

    assert intel_observability.predictions_low_confidence_total == 10
    assert intel_observability.predictions_high_confidence_total >= 120  # 100 prior + 20 new
    print(f"    Confidence Stratification: High(>=0.85)={intel_observability.predictions_high_confidence_total} | Low(<0.65)={intel_observability.predictions_low_confidence_total}")
    print("    [PASS] Confidence boundary classification verified.")

    # 5. Dynamic ML Engine Health Assessment
    print("\n[5/7] Testing ML Engine Dynamic Health Transitions...")
    # Baseline: Healthy
    assert intel_observability.ml_health_state == MLHealthStatus.HEALTHY

    # Induce Degraded State (Latency spike > 1.5s)
    intel_observability.record_ml_prediction("v1.0", "LATERAL_MOVEMENT", 0.90, duration_sec=1.8, success=True)
    assert intel_observability.ml_health_state == MLHealthStatus.DEGRADED
    print(f"    Spike Latency Trigger: State={intel_observability.ml_health_state.value} | Msg={intel_observability.ml_health_message}")

    # Induce Error State (Error rate > 30%)
    intel_observability.ml_recent_inferences = 10
    intel_observability.ml_recent_errors = 4  # 40% error rate
    intel_observability._evaluate_ml_health(0.020)
    assert intel_observability.ml_health_state == MLHealthStatus.ERROR
    print(f"    Error Rate Trigger: State={intel_observability.ml_health_state.value} | Msg={intel_observability.ml_health_message}")

    # Induce Unavailable State (Artifacts missing)
    intel_observability.ml_model_artifacts_available = False
    intel_observability._evaluate_ml_health(0.010)
    assert intel_observability.ml_health_state == MLHealthStatus.UNAVAILABLE
    print(f"    Artifact Missing Trigger: State={intel_observability.ml_health_state.value} | Msg={intel_observability.ml_health_message}")

    # Recover to Healthy
    intel_observability.ml_model_artifacts_available = True
    intel_observability.ml_recent_errors = 0
    intel_observability.ml_recent_inferences = 100
    intel_observability._evaluate_ml_health(0.010)
    assert intel_observability.ml_health_state == MLHealthStatus.HEALTHY
    print("    [PASS] ML health transitions verified.")

    # 6. XAI & Quantitative Risk Breakdown
    print("\n[6/7] Auditing XAI & Multi-Factor Risk Severity Stratification...")
    intel_observability.record_xai_explanation(duration_sec=0.035, success=True)
    intel_observability.record_xai_explanation(duration_sec=0.010, success=False)
    assert intel_observability.xai_explanations_total == 1
    assert intel_observability.xai_failures_total == 1

    # Record risk calculations across severity levels
    intel_observability.record_risk_calculation("LOW", 0.004, success=True)
    intel_observability.record_risk_calculation("MEDIUM", 0.005, success=True)
    intel_observability.record_risk_calculation("HIGH", 0.006, success=True)
    intel_observability.record_risk_calculation("CRITICAL", 0.008, success=True)
    intel_observability.record_risk_calculation("CRITICAL", 0.002, success=False)

    assert intel_observability.risk_calculations_total == 4
    assert intel_observability.risk_calculation_failures_total == 1
    assert intel_observability.risk_severity_counts["CRITICAL"] == 1
    assert intel_observability.risk_severity_counts["HIGH"] == 1
    print(f"    Risk Breakdown: LOW={intel_observability.risk_severity_counts['LOW']} | MEDIUM={intel_observability.risk_severity_counts['MEDIUM']} | HIGH={intel_observability.risk_severity_counts['HIGH']} | CRITICAL={intel_observability.risk_severity_counts['CRITICAL']}")
    print("    [PASS] XAI and Risk engines monitored.")

    # 7. OpenMetrics Exposition Rendering
    print("\n[7/7] Generating Prometheus :9090 Exposition Output...")
    rendered = intel_observability.render_intelligence_exposition()
    assert "# TYPE twin_updates_total counter" in rendered
    assert "# TYPE devices_tracked gauge" in rendered
    assert "# TYPE simulation_runs_active gauge" in rendered
    assert "# TYPE ml_inference_latency_seconds histogram" in rendered
    assert "# TYPE predictions_low_confidence_total counter" in rendered
    assert "# TYPE ml_engine_health gauge" in rendered
    assert "# TYPE xai_explanations_total counter" in rendered
    assert "# TYPE risk_calculations_by_severity counter" in rendered
    assert 'risk_calculations_by_severity{severity="CRITICAL"} 1' in rendered
    print("    Sample Exposition Lines:\n    " + "\n    ".join(rendered.splitlines()[:6]))
    print("    [PASS] Prometheus exposition format validated.")

    print("\n" + "=" * 80)
    print("       ALL DAY 200 TWIN, SIMULATION & ML OBSERVABILITY TESTS COMPLETED")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day200_suite())