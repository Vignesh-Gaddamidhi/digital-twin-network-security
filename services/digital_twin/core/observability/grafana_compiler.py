import json
from pathlib import Path
from typing import Dict, Any, List

REQUIRED_SECTIONS = [
    "SYSTEM HEALTH OVERVIEW",
    "API INFRASTRUCTURE & GOLDEN SIGNALS",
    "API ERROR STRATIFICATION",
    "POSTGRESQL PERSISTENCE",
    "DATABASE QUERY EXECUTION",
    "REDIS CLUSTER",
    "EVENT-STREAM THROUGHPUT",
    "DIGITAL TWIN TOPOLOGY",
    "ML INFERENCE LATENCY",
    "ATTACK SIMULATION LIFECYCLE",
    "WEBSOCKET GATEWAY",
    "HOST & PROCESS RESOURCE CONSTRAINTS"
]

REQUIRED_METRICS = [
    "cybertwin_service_health",
    "api_requests_total",
    "api_request_duration_seconds_bucket",
    "api_active_requests",
    "api_client_errors_total",
    "api_server_errors_total",
    "db_pool_active",
    "db_queries_total",
    "redis_connected_clients",
    "events_published_total",
    "events_dropped_total",
    "devices_tracked",
    "predictions_total",
    "simulation_runs_active",
    "ws_active_connections",
    "host_cpu_percent",
    "host_memory_percent"
]

class GrafanaDashboardCompiler:
    def __init__(self, dashboard_path: str):
        self.dashboard_path = Path(dashboard_path)
        self.raw_data: Dict[str, Any] = {}

    def load_and_validate(self) -> Dict[str, Any]:
        if not self.dashboard_path.exists():
            raise FileNotFoundError(f"Dashboard file not found: {self.dashboard_path}")

        with open(self.dashboard_path, "r", encoding="utf-8") as f:
            self.raw_data = json.load(f)

        assert self.raw_data.get("title") == "CYBERTWIN — SYSTEM HEALTH"
        assert self.raw_data.get("refresh") == "10s"
        assert "5m" in self.raw_data.get("timepicker", {}).get("time_options", [])
        assert "24h" in self.raw_data.get("timepicker", {}).get("time_options", [])

        panels = self.raw_data.get("panels", [])
        assert len(panels) >= 12, f"Expected at least 12 panels, got {len(panels)}"

        # Verify all required metrics are targeted across panels
        all_expressions = []
        for p in panels:
            for t in p.get("targets", []):
                all_expressions.append(t.get("expr", ""))

        full_expr_str = " ".join(all_expressions)
        for m in REQUIRED_METRICS:
            assert m in full_expr_str, f"Missing required PromQL metric: {m}"

        return {
            "title": self.raw_data.get("title"),
            "total_panels": len(panels),
            "refresh": self.raw_data.get("refresh"),
            "valid_queries": len(all_expressions)
        }

grafana_compiler = GrafanaDashboardCompiler(
    str(Path(__file__).resolve().parent / "dashboards" / "cybertwin_system_health.json")
)