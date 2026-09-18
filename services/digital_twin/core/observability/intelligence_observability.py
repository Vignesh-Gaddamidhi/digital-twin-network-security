import time
import math
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple

class MLHealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"

class SimulationScenarioEnum(str, Enum):
    NORMAL = "NORMAL"
    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    CONNECTION_ANOMALY = "CONNECTION_ANOMALY"
    PORT_ANOMALY = "PORT_ANOMALY"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    REPEATED_CONNECTION = "REPEATED_CONNECTION"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE_LIKE = "BRUTE_FORCE_LIKE"
    DOS_LIKE = "DOS_LIKE"
    DNS_ANOMALY = "DNS_ANOMALY"
    BEACONING = "BEACONING"
    LATERAL_MOVEMENT_LIKE = "LATERAL_MOVEMENT_LIKE"
    EXFILTRATION_LIKE = "EXFILTRATION_LIKE"

INTEL_LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

class IntelligenceAndSimulationObservability:
    """
    Unified telemetry collector for Digital Twin state mutations,
    Attack Scenario Simulations, ML Inference/Confidence, XAI Drivers, and Risk Engine Scoring.
    """
    def __init__(self):
        # 1. Digital Twin Metrics
        self.twin_updates_total: int = 0
        self.twin_update_failures_total: int = 0
        self.devices_tracked: int = 0
        self.active_connections: int = 0
        self.state_transitions_total: int = 0
        self.state_transition_failures_total: int = 0
        
        # Histograms for Twin updates and sync paths:
        # Path keys: "twin_update", "sim_redis_twin", "twin_postgres", "twin_ws_soc"
        self.twin_sync_latency_hist: Dict[str, Dict[str, Any]] = {}

        # 2. Simulation Monitoring
        self.simulation_runs_total: Dict[str, int] = {}
        self.simulation_runs_active: int = 0
        self.simulation_runs_completed: Dict[str, int] = {}
        self.simulation_runs_failed: Dict[str, int] = {}
        self.simulation_events_total: Dict[str, int] = {}
        self.simulation_duration_hist: Dict[str, Dict[str, Any]] = {}
        self.simulation_event_latency_hist: Dict[str, Dict[str, Any]] = {}

        # 3. ML Prediction Metrics
        # (model_version, attack_category) -> {buckets, sum, count, samples}
        self.ml_inference_latency_hist: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.predictions_total: Dict[Tuple[str, str], int] = {}
        self.predictions_failed_total: Dict[Tuple[str, str], int] = {}
        self.predictions_low_confidence_total: int = 0
        self.predictions_high_confidence_total: int = 0

        # Dynamic ML Engine Health State
        self.ml_model_artifacts_available: bool = True
        self.ml_recent_errors: int = 0
        self.ml_recent_inferences: int = 0
        self.ml_health_state: MLHealthStatus = MLHealthStatus.HEALTHY
        self.ml_health_message: str = "Models loaded and responding"

        # 4. XAI Explanation Metrics
        self.xai_explanations_total: int = 0
        self.xai_failures_total: int = 0
        self.xai_latency_hist: Dict[str, Any] = {
            "buckets": {b: 0 for b in INTEL_LATENCY_BUCKETS},
            "sum": 0.0,
            "count": 0,
            "samples": []
        }

        # 5. Risk Engine Metrics
        self.risk_calculations_total: int = 0
        self.risk_calculation_failures_total: int = 0
        self.risk_severity_counts: Dict[str, int] = {
            "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0
        }
        self.risk_latency_hist: Dict[str, Any] = {
            "buckets": {b: 0 for b in INTEL_LATENCY_BUCKETS},
            "sum": 0.0,
            "count": 0,
            "samples": []
        }

    # ------------------ DIGITAL TWIN TELEMETRY ------------------

    def record_twin_update(self, duration_sec: float, success: bool = True):
        if success:
            self.twin_updates_total += 1
        else:
            self.twin_update_failures_total += 1
        self._add_to_hist(self.twin_sync_latency_hist, "twin_update", duration_sec)

    def record_twin_sync_stage(self, stage: str, duration_sec: float):
        """Record sync path latency (e.g. sim_redis_twin, twin_postgres, twin_ws_soc)."""
        self._add_to_hist(self.twin_sync_latency_hist, stage, duration_sec)

    def update_twin_topology_counts(self, devices: int, connections: int):
        self.devices_tracked = max(0, devices)
        self.active_connections = max(0, connections)

    def record_state_transition(self, success: bool = True):
        if success:
            self.state_transitions_total += 1
        else:
            self.state_transition_failures_total += 1

    # ------------------ SIMULATION TELEMETRY ------------------

    def record_simulation_start(self, scenario: str):
        sc_name = scenario.upper()
        self.simulation_runs_total[sc_name] = self.simulation_runs_total.get(sc_name, 0) + 1
        self.simulation_runs_active += 1

    def record_simulation_end(self, scenario: str, duration_sec: float, events_generated: int, success: bool = True):
        sc_name = scenario.upper()
        self.simulation_runs_active = max(0, self.simulation_runs_active - 1)
        if success:
            self.simulation_runs_completed[sc_name] = self.simulation_runs_completed.get(sc_name, 0) + 1
        else:
            self.simulation_runs_failed[sc_name] = self.simulation_runs_failed.get(sc_name, 0) + 1
        
        self.simulation_events_total[sc_name] = self.simulation_events_total.get(sc_name, 0) + events_generated
        self._add_to_hist(self.simulation_duration_hist, sc_name, duration_sec)

    def record_simulation_event_latency(self, scenario: str, latency_sec: float):
        self._add_to_hist(self.simulation_event_latency_hist, scenario.upper(), latency_sec)

    # ------------------ ML INFERENCE & HEALTH ------------------

    def record_ml_prediction(
        self,
        model_version: str,
        category: str,
        confidence: float,
        duration_sec: float,
        success: bool = True
    ):
        key = (model_version, category.upper())
        self.ml_recent_inferences += 1
        self.predictions_total[key] = self.predictions_total.get(key, 0) + 1

        if not success:
            self.ml_recent_errors += 1
            self.predictions_failed_total[key] = self.predictions_failed_total.get(key, 0) + 1
        else:
            if confidence >= 0.85:
                self.predictions_high_confidence_total += 1
            elif confidence < 0.65:
                self.predictions_low_confidence_total += 1

        self._add_to_hist(self.ml_inference_latency_hist, key, duration_sec)
        self._evaluate_ml_health(duration_sec)

    def calculate_ml_latency_quantiles(self, model_version: str, category: str) -> Dict[str, float]:
        key = (model_version, category.upper())
        hist = self.ml_inference_latency_hist.get(key)
        if not hist or not hist["samples"]:
            return {"avg": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}

        sorted_s = sorted(hist["samples"])
        n = len(sorted_s)

        def q(p: float) -> float:
            idx = int(math.ceil(p * n)) - 1
            return sorted_s[max(0, min(idx, n - 1))]

        return {
            "avg": round(hist["sum"] / hist["count"], 5),
            "p50": round(q(0.50), 5),
            "p95": round(q(0.95), 5),
            "p99": round(q(0.99), 5)
        }

    def _evaluate_ml_health(self, last_latency_sec: float):
        """Evaluate real-time ML Engine state dynamically based on artifact availability, latency & errors."""
        if not self.ml_model_artifacts_available:
            self.ml_health_state = MLHealthStatus.UNAVAILABLE
            self.ml_health_message = "Model weight files missing from artifacts storage"
            return

        err_rate = (self.ml_recent_errors / max(1, self.ml_recent_inferences))
        if err_rate > 0.30:
            self.ml_health_state = MLHealthStatus.ERROR
            self.ml_health_message = f"Critical inference error rate: {err_rate*100:.1f}%"
        elif err_rate > 0.05 or last_latency_sec > 1.5:
            self.ml_health_state = MLHealthStatus.DEGRADED
            self.ml_health_message = f"Elevated latency ({last_latency_sec*1000:.1f}ms) or error rate ({err_rate*100:.1f}%)"
        else:
            self.ml_health_state = MLHealthStatus.HEALTHY
            self.ml_health_message = "Optimal execution within SLA bounds"

    # ------------------ XAI & RISK TELEMETRY ------------------

    def record_xai_explanation(self, duration_sec: float, success: bool = True):
        if success:
            self.xai_explanations_total += 1
        else:
            self.xai_failures_total += 1
        self._add_to_single_hist(self.xai_latency_hist, duration_sec)

    def record_risk_calculation(self, severity: str, duration_sec: float, success: bool = True):
        sev = severity.upper()
        if success:
            self.risk_calculations_total += 1
            if sev in self.risk_severity_counts:
                self.risk_severity_counts[sev] += 1
        else:
            self.risk_calculation_failures_total += 1
        self._add_to_single_hist(self.risk_latency_hist, duration_sec)

    # ------------------ HISTOGRAM HELPERS ------------------

    def _add_to_hist(self, target: Dict[Any, Dict[str, Any]], key: Any, val: float):
        if key not in target:
            target[key] = {
                "buckets": {b: 0 for b in INTEL_LATENCY_BUCKETS},
                "sum": 0.0,
                "count": 0,
                "samples": []
            }
        h = target[key]
        h["sum"] += val
        h["count"] += 1
        h["samples"].append(val)
        if len(h["samples"]) > 1000:
            h["samples"].pop(0)
        for b in INTEL_LATENCY_BUCKETS:
            if val <= b:
                h["buckets"][b] += 1

    def _add_to_single_hist(self, target: Dict[str, Any], val: float):
        target["sum"] += val
        target["count"] += 1
        target["samples"].append(val)
        if len(target["samples"]) > 1000:
            target["samples"].pop(0)
        for b in INTEL_LATENCY_BUCKETS:
            if val <= b:
                target["buckets"][b] += 1

    # ------------------ PROMETHEUS EXPOSITION ------------------

    def render_intelligence_exposition(self) -> str:
        lines = []

        # 1. Digital Twin Metrics
        lines.append("# HELP twin_updates_total Total state mutations applied to Digital Twin graph.")
        lines.append("# TYPE twin_updates_total counter")
        lines.append(f"twin_updates_total {self.twin_updates_total}")

        lines.append("# HELP twin_update_failures_total Total failed state mutation attempts.")
        lines.append("# TYPE twin_update_failures_total counter")
        lines.append(f"twin_update_failures_total {self.twin_update_failures_total}")

        lines.append("# HELP devices_tracked Current active topology devices mapped in memory.")
        lines.append("# TYPE devices_tracked gauge")
        lines.append(f"devices_tracked {self.devices_tracked}")

        lines.append("# HELP active_connections Current active network edges monitored in Twin topology.")
        lines.append("# TYPE active_connections gauge")
        lines.append(f"active_connections {self.active_connections}")

        lines.append("# HELP state_transitions_total Total successful entity state machine updates.")
        lines.append("# TYPE state_transitions_total counter")
        lines.append(f"state_transitions_total {self.state_transitions_total}")

        lines.append("# HELP state_transition_failures_total Total illegal or rejected entity state transitions.")
        lines.append("# TYPE state_transition_failures_total counter")
        lines.append(f"state_transition_failures_total {self.state_transition_failures_total}")

        lines.append("# HELP twin_sync_latency_seconds Latency of digital twin update and synchronization pipelines.")
        lines.append("# TYPE twin_sync_latency_seconds histogram")
        for stage, h in self.twin_sync_latency_hist.items():
            acc = 0
            for b in INTEL_LATENCY_BUCKETS:
                acc += h["buckets"][b]
                lines.append(f'twin_sync_latency_seconds_bucket{{stage="{stage}",le="{b}"}} {acc}')
            lines.append(f'twin_sync_latency_seconds_bucket{{stage="{stage}",le="+Inf"}} {h["count"]}')
            lines.append(f'twin_sync_latency_seconds_sum{{stage="{stage}"}} {round(h["sum"], 5)}')
            lines.append(f'twin_sync_latency_seconds_count{{stage="{stage}"}} {h["count"]}')

        # 2. Simulation Monitoring
        lines.append("# HELP simulation_runs_active Number of attack simulations actively executing.")
        lines.append("# TYPE simulation_runs_active gauge")
        lines.append(f"simulation_runs_active {self.simulation_runs_active}")

        lines.append("# HELP simulation_runs_total Total started attack simulation experiments by scenario.")
        lines.append("# TYPE simulation_runs_total counter")
        for sc, cnt in self.simulation_runs_total.items():
            lines.append(f'simulation_runs_total{{scenario="{sc}"}} {cnt}')

        lines.append("# HELP simulation_runs_completed Total cleanly finished simulation experiments.")
        lines.append("# TYPE simulation_runs_completed counter")
        for sc, cnt in self.simulation_runs_completed.items():
            lines.append(f'simulation_runs_completed{{scenario="{sc}"}} {cnt}')

        lines.append("# HELP simulation_events_total Total synthetic attack telemetry frames emitted.")
        lines.append("# TYPE simulation_events_total counter")
        for sc, cnt in self.simulation_events_total.items():
            lines.append(f'simulation_events_total{{scenario="{sc}"}} {cnt}')

        # 3. ML Prediction Metrics
        lines.append("# HELP ml_inference_latency_seconds Latency of inference calls across model versions and categories.")
        lines.append("# TYPE ml_inference_latency_seconds histogram")
        for (ver, cat), h in self.ml_inference_latency_hist.items():
            acc = 0
            for b in INTEL_LATENCY_BUCKETS:
                acc += h["buckets"][b]
                lines.append(f'ml_inference_latency_seconds_bucket{{version="{ver}",category="{cat}",le="{b}"}} {acc}')
            lines.append(f'ml_inference_latency_seconds_bucket{{version="{ver}",category="{cat}",le="+Inf"}} {h["count"]}')
            lines.append(f'ml_inference_latency_seconds_sum{{version="{ver}",category="{cat}"}} {round(h["sum"], 5)}')
            lines.append(f'ml_inference_latency_seconds_count{{version="{ver}",category="{cat}"}} {h["count"]}')

        lines.append("# HELP predictions_total Total model inference classifications executed.")
        lines.append("# TYPE predictions_total counter")
        for (ver, cat), cnt in self.predictions_total.items():
            lines.append(f'predictions_total{{version="{ver}",category="{cat}"}} {cnt}')

        lines.append("# HELP predictions_low_confidence_total Predictions executed with confidence below 0.65.")
        lines.append("# TYPE predictions_low_confidence_total counter")
        lines.append(f"predictions_low_confidence_total {self.predictions_low_confidence_total}")

        lines.append("# HELP predictions_high_confidence_total Predictions executed with confidence 0.85 or above.")
        lines.append("# TYPE predictions_high_confidence_total counter")
        lines.append(f"predictions_high_confidence_total {self.predictions_high_confidence_total}")

        lines.append("# HELP ml_engine_health Status indicator of ML subsystem (1=Healthy, 0=Degraded/Down).")
        lines.append("# TYPE ml_engine_health gauge")
        ml_score = 1 if self.ml_health_state == MLHealthStatus.HEALTHY else 0
        lines.append(f'ml_engine_health{{status="{self.ml_health_state.value}"}} {ml_score}')

        # 4. XAI Metrics
        lines.append("# HELP xai_explanations_total Total TreeSHAP explanations generated.")
        lines.append("# TYPE xai_explanations_total counter")
        lines.append(f"xai_explanations_total {self.xai_explanations_total}")

        lines.append("# HELP xai_failures_total Total failed explanation generation attempts.")
        lines.append("# TYPE xai_failures_total counter")
        lines.append(f"xai_failures_total {self.xai_failures_total}")

        # 5. Risk Engine Metrics
        lines.append("# HELP risk_calculations_total Total multi-factor risk calculations executed.")
        lines.append("# TYPE risk_calculations_total counter")
        lines.append(f"risk_calculations_total {self.risk_calculations_total}")

        lines.append("# HELP risk_calculations_by_severity Breakdown of risk assessments by severity tier.")
        lines.append("# TYPE risk_calculations_by_severity counter")
        for sev, cnt in self.risk_severity_counts.items():
            lines.append(f'risk_calculations_by_severity{{severity="{sev}"}} {cnt}')

        return "\n".join(lines) + "\n"

intel_observability = IntelligenceAndSimulationObservability()