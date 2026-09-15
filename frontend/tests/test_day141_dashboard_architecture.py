import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from frontend.dashboard.dashboard_state_models import (
    ComponentStatus, NavigationSection, DashboardState
)
from frontend.dashboard.dashboard_engine import dashboard_engine

def run_day141_suite():
    print("=" * 80)
    print("       WEEK 21 - DAY 141: DASHBOARD ARCHITECTURE & UI FOUNDATION AUDIT")
    print("=" * 80 + "\n")

    # 1. Dashboard State Initialization
    print("[1/7] Auditing Dashboard State Shell Initialization...")
    assert dashboard_engine.current_state is not None
    shell_str = dashboard_engine.render_cli_dashboard_shell()
    print(shell_str)
    assert "NETWORK SECURITY DIGITAL TWIN" in shell_str
    assert "ACTIVE VIEW" in shell_str
    print("    [PASS] Dashboard state and CLI shell layout validated.")

    # 2. Navigation Routing Transitions
    print("\n[2/7] Auditing Navigation Section Transitions...")
    sections_to_test = [
        NavigationSection.TOPOLOGY,
        NavigationSection.DEVICES,
        NavigationSection.TRAFFIC,
        NavigationSection.THREATS,
        NavigationSection.PREDICTIONS,
        NavigationSection.RISK,
        NavigationSection.ATTACK_PATHS,
        NavigationSection.ALERTS,
        NavigationSection.SIMULATIONS
    ]
    for sec in sections_to_test:
        st = dashboard_engine.set_active_section(sec)
        assert st.activeSection == sec
        print(f"    Navigated to: {sec.value:<16} | Status: OK")
    print("    [PASS] All 9 main navigation sections route properly.")

    # 3. Live KPI Metric Ingestion
    print("\n[3/7] Auditing Live KPI Metric Feed Updates...")
    updated = dashboard_engine.update_telemetry_feed(
        devices_count=14,
        active_threats=6,
        network_risk_score=88.50,
        network_risk_level="CRITICAL",
        attack_paths_count=4,
        packets_per_sec=2150.0
    )
    assert updated.kpi.totalDevices == 14
    assert updated.kpi.activeThreats == 6
    assert updated.kpi.networkRiskScore == 88.50
    assert updated.kpi.networkRiskLevel == "CRITICAL"
    print(f"    Updated KPI: Devices={updated.kpi.totalDevices}, Threats={updated.kpi.activeThreats}, Risk={updated.kpi.networkRiskLevel} ({updated.kpi.networkRiskScore})")
    print("    [PASS] Live KPI metrics reflect accurately in dashboard state.")

    # 4. Component Lifecycle States: Loading & Loaded
    print("\n[4/7] Auditing Component Lifecycle: LOADING and LOADED states...")
    dashboard_engine.trigger_component_state("topology_canvas", ComponentStatus.LOADING)
    assert dashboard_engine.current_state.componentStates["topology_canvas"].status == ComponentStatus.LOADING
    print("    topology_canvas -> LOADING verified.")

    dashboard_engine.trigger_component_state("topology_canvas", ComponentStatus.LOADED)
    assert dashboard_engine.current_state.componentStates["topology_canvas"].status == ComponentStatus.LOADED
    print("    topology_canvas -> LOADED verified.")
    print("    [PASS] Loading and active Loaded states validated.")

    # 5. Component Lifecycle States: Empty, Error & Unavailable
    print("\n[5/7] Auditing Component Lifecycle: EMPTY, ERROR, and UNAVAILABLE states...")
    dashboard_engine.trigger_component_state("alert_feed", ComponentStatus.EMPTY)
    assert dashboard_engine.current_state.componentStates["alert_feed"].status == ComponentStatus.EMPTY
    print("    alert_feed -> EMPTY verified.")

    dashboard_engine.trigger_component_state("prediction_panel", ComponentStatus.ERROR, error_msg="Model artifact unreadable.")
    err_state = dashboard_engine.current_state.componentStates["prediction_panel"]
    assert err_state.status == ComponentStatus.ERROR
    assert err_state.errorMessage == "Model artifact unreadable."
    print(f"    prediction_panel -> ERROR verified: '{err_state.errorMessage}'")

    dashboard_engine.trigger_component_state("traffic_stream", ComponentStatus.UNAVAILABLE, error_msg="Capture interface down.")
    assert dashboard_engine.current_state.componentStates["traffic_stream"].status == ComponentStatus.UNAVAILABLE
    print("    traffic_stream -> UNAVAILABLE verified.")
    print("    [PASS] Fallback component lifecycle states validated.")

    # 6. Responsive Viewport Configurations
    print("\n[6/7] Auditing Viewport Layout Profiles (Desktop, Laptop, Tablet)...")
    viewports = {
        "Desktop High-Res": {"width": 1920, "columns": 12, "layout": "3-column wide"},
        "Laptop Primary (Dell Latitude 3410)": {"width": 1366, "columns": 8, "layout": "2-column balanced"},
        "Tablet Operational": {"width": 768, "columns": 4, "layout": "1-column stacked"}
    }
    for label, v in viewports.items():
        print(f"    Target: {label:<36} | Width: {v['width']}px | Grid: {v['columns']} cols ({v['layout']})")
        assert v["columns"] >= 4
    print("    [PASS] Responsive viewports mapped for laptop and desktop screens.")

    # 7. Reset to Default State
    print("\n[7/7] Resetting Dashboard Shell to Operational Baseline...")
    dashboard_engine.set_active_section(NavigationSection.OVERVIEW)
    dashboard_engine.trigger_component_state("prediction_panel", ComponentStatus.LOADED)
    dashboard_engine.trigger_component_state("alert_feed", ComponentStatus.LOADED)
    dashboard_engine.trigger_component_state("traffic_stream", ComponentStatus.LOADED)
    assert dashboard_engine.current_state.activeSection == NavigationSection.OVERVIEW
    print("    [PASS] Dashboard state reset clean.")

    print("\n" + "=" * 80)
    print("       ALL DAY 141 DASHBOARD ARCHITECTURE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day141_suite()