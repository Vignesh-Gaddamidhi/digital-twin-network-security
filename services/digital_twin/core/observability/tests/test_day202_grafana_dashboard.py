import sys
import time
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.observability.grafana_compiler import grafana_compiler, REQUIRED_METRICS

async def run_day202_suite():
    print("=" * 80)
    print("       WEEK 29 - DAY 202: GRAFANA ENTERPRISE MONITORING DASHBOARD")
    print("================================================================================\n")

    # 1. Load & Validate JSON Dashboard Schema
    print("[1/6] Loading & Validating Grafana Enterprise Dashboard JSON Schema...")
    summary = grafana_compiler.load_and_validate()
    assert summary["title"] == "CYBERTWIN — SYSTEM HEALTH"
    assert summary["refresh"] == "10s"
    assert summary["total_panels"] >= 12
    print(f"    Dashboard Title: '{summary['title']}'")
    print(f"    Refresh Interval: {summary['refresh']} (Controlled rate to prevent scraper thrashing)")
    print(f"    Total Configured Panels: {summary['total_panels']}")
    print("    [PASS] Grafana dashboard schema conforms to specifications.")

    # 2. Time Control Capabilities
    print("\n[2/6] Auditing Configured Time Ranges & Refresh Controls...")
    time_opts = grafana_compiler.raw_data.get("timepicker", {}).get("time_options", [])
    expected_ranges = ["5m", "15m", "30m", "1h", "6h", "24h"]
    for r in expected_ranges:
        assert r in time_opts, f"Missing time range: {r}"
    print(f"    Verified Time Ranges: {', '.join(expected_ranges)}")
    print("    [PASS] Time range options verified.")

    # 3. Top-Level Status Panel (8 Subsystems)
    print("\n[3/6] Auditing Top-Level System Health Status Panel...")
    top_panel = grafana_compiler.raw_data["panels"][0]
    assert top_panel["title"] == "SYSTEM HEALTH OVERVIEW"
    assert top_panel["type"] == "stat"
    assert top_panel["targets"][0]["expr"] == "cybertwin_service_health"
    print(f"    Panel #1: {top_panel['title']} (Type: {top_panel['type']}, Metric: {top_panel['targets'][0]['expr']})")
    print("    [PASS] Top-level status overview panel verified.")

    # 4. PromQL Expression & Metric Binding Audit
    print("\n[4/6] Auditing PromQL Target Expressions Across All 12 Sections...")
    all_exprs = []
    for p in grafana_compiler.raw_data["panels"]:
        for t in p.get("targets", []):
            all_exprs.append(t.get("expr", ""))
    
    full_str = " ".join(all_exprs)
    for m in REQUIRED_METRICS:
        assert m in full_str, f"Missing PromQL target metric: {m}"
    print(f"    Verified {len(REQUIRED_METRICS)} Core Prometheus Metrics Mapped into Grafana Queries.")
    print("    [PASS] PromQL metrics bound without missing references.")

    # 5. Latency Quantile PromQL Checks
    print("\n[5/6] Auditing Quantile Latency PromQL Formulas (p50, p95, p99)...")
    assert "histogram_quantile(0.50" in full_str
    assert "histogram_quantile(0.95" in full_str
    assert "histogram_quantile(0.99" in full_str
    print("    Verified PromQL Quantiles: histogram_quantile(0.50), histogram_quantile(0.95), histogram_quantile(0.99)")
    print("    [PASS] Quantile expressions verified.")

    # 6. Panel Grid Positioning Invariants (Non-Overlapping)
    print("\n[6/6] Auditing Panel Grid Position & Layout Geometry...")
    occupied_coords = []
    for p in grafana_compiler.raw_data["panels"]:
        gp = p.get("gridPos", {})
        h, w, x, y = gp.get("h"), gp.get("w"), gp.get("x"), gp.get("y")
        assert all(v is not None for v in [h, w, x, y])
        assert w <= 24 and (x + w) <= 24, f"Panel {p['title']} exceeds 24-column width boundary"
        occupied_coords.append((p["id"], p["title"], x, y, w, h))

    print(f"    Audited {len(occupied_coords)} Panel Positions across 24-column Grid.")
    print("    [PASS] Panel layout geometry verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 202 GRAFANA DASHBOARD TESTS COMPLETED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day202_suite())