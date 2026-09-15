from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from frontend.dashboard.dashboard_state_models import (
    ComponentStatus, NavigationSection, HeaderInfo, DashboardKPISummary,
    ComponentState, DashboardState
)

class DashboardEngine:
    """Manages dashboard lifecycle, navigation routing, fallback states, and data mapping."""

    def __init__(self):
        self.current_state = DashboardState()
        self._initialize_component_states()

    def _initialize_component_states(self):
        components = [
            "kpi_bar", "topology_canvas", "device_table", "traffic_stream",
            "threat_timeline", "prediction_panel", "risk_matrix",
            "attack_path_inspector", "alert_feed", "simulation_controller"
        ]
        for c in components:
            self.current_state.set_component_status(c, ComponentStatus.LOADED)

    def set_active_section(self, section: NavigationSection) -> DashboardState:
        self.current_state.activeSection = section
        self.current_state.header.lastUpdated = datetime.now(timezone.utc).isoformat()
        return self.current_state

    def update_telemetry_feed(
        self,
        devices_count: int,
        active_threats: int,
        network_risk_score: float,
        network_risk_level: str,
        attack_paths_count: int,
        packets_per_sec: float
    ) -> DashboardState:
        self.current_state.kpi = DashboardKPISummary(
            totalDevices=devices_count,
            quarantinedDevices=0,
            activeThreats=active_threats,
            networkRiskScore=network_risk_score,
            networkRiskLevel=network_risk_level,
            activeAttackPaths=attack_paths_count,
            packetsPerSecond=packets_per_sec
        )
        self.current_state.header.lastUpdated = datetime.now(timezone.utc).isoformat()
        return self.current_state

    def trigger_component_state(
        self,
        component_id: str,
        status: ComponentStatus,
        error_msg: Optional[str] = None
    ) -> DashboardState:
        self.current_state.set_component_status(component_id, status, error_msg)
        return self.current_state

    def render_cli_dashboard_shell(self) -> str:
        s = self.current_state
        k = s.kpi
        h = s.header
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            f"║ {h.systemTitle.upper():<54} [{h.systemStatus}] ║",
            f"║ Mode: {h.environment:<18} Simulation: {h.simulationStatus:<10} Analyst: {h.currentAnalyst:<16} ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ DEVICES: {k.totalDevices:02d}      │ THREATS: {k.activeThreats:02d}     │ RISK: {k.networkRiskLevel:<8} ({k.networkRiskScore:5.2f}) │ ATTACKS: {k.activeAttackPaths:02d}  ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ ACTIVE VIEW: [{s.activeSection.value}]                                             ║",
            "║ NAVIGATION: Overview │ Topology │ Devices │ Traffic │ Threats │ Predictions ║",
            "║             Risk │ Attack Paths │ Alerts │ Simulations │ Settings            ║",
            "╚══════════════════════════════════════════════════════════════════════════════╝"
        ]
        return "\n".join(lines)

dashboard_engine = DashboardEngine()