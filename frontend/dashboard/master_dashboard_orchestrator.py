from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid

from frontend.dashboard.kpi_summary_engine import kpi_summary_engine
from frontend.dashboard.kpi_models import MasterKPISnapshot
from frontend.topology.topology_canvas_engine import topology_canvas_engine
from frontend.topology.topology_models import LiveTopologySnapshot
from frontend.traffic.traffic_monitoring_engine import traffic_monitoring_engine
from frontend.traffic.traffic_models import LiveTrafficPanelSnapshot
from frontend.threats.threat_timeline_engine import threat_timeline_engine
from frontend.threats.threat_models import ThreatTimelineItem
from frontend.predictions.prediction_panel_engine import prediction_panel_engine
from frontend.predictions.prediction_models import LivePredictionDetail
from frontend.attacks.attack_path_dashboard_engine import attack_path_dashboard_engine
from frontend.attacks.attack_path_dashboard_models import AttackPathDashboardSnapshot
from frontend.alerts.alert_center_engine import alert_center_engine
from frontend.alerts.alert_center_models import SecurityAlertItem
from frontend.simulations.simulation_control_engine import simulation_control_engine
from frontend.simulations.simulation_models import SimulationLiveStateView
from frontend.dashboard.dashboard_integration_engine import dashboard_integration_engine
from frontend.dashboard.integration_models import SubsystemHealthPanel, PipelineObservabilityMetrics

class MasterDashboardUnifiedView:
    def __init__(self):
        self.session_id = f"SOC-SES-{uuid.uuid4().hex[:6].upper()}"

    def assemble_full_dashboard(self) -> Dict[str, Any]:
        kpi = kpi_summary_engine.aggregate_live_kpis()
        topology = topology_canvas_engine.generate_live_topology()
        traffic = traffic_monitoring_engine.generate_traffic_snapshot()
        timeline = threat_timeline_engine.get_timeline()
        prediction = prediction_panel_engine.get_live_prediction("WEB-01")
        attack_paths = attack_path_dashboard_engine.generate_dashboard_snapshot()
        alerts = alert_center_engine.alerts
        sim_state = simulation_control_engine.live_state
        health = dashboard_integration_engine.get_subsystem_health()
        obs = dashboard_integration_engine.observability

        return {
            "systemStatus": "ACTIVE",
            "environment": "LAB-SIMULATION",
            "lastUpdated": datetime.now(timezone.utc).isoformat(),
            "kpi": kpi.model_dump(),
            "topology": topology.model_dump(),
            "traffic": traffic.model_dump(),
            "threatTimeline": [t.model_dump() for t in timeline[:6]],
            "prediction": prediction.model_dump(),
            "attackPaths": attack_paths.model_dump(),
            "alerts": [a.model_dump() for a in alerts[:6]],
            "simulation": sim_state.model_dump(),
            "health": health.model_dump(),
            "observability": obs.model_dump()
        }

    def render_cli_soc_command_center(self) -> str:
        data = self.assemble_full_dashboard()
        k = data["kpi"]
        h = data["health"]
        top_path = data["attackPaths"]["rankedPaths"][0] if data["attackPaths"]["rankedPaths"] else None
        chain_str = " ──> ".join(top_path["nodeSequence"]) if top_path else "NONE"
        pred = data["prediction"]

        lines = [
            "┌────────────────────────────────────────────────────────────────────────────┐",
            "│ Network Security Digital Twin                              ● SYSTEM ACTIVE │",
            "├──────────────┬──────────────┬──────────────┬───────────────────────────────┤",
            f"│   DEVICES    │   THREATS    │     RISK     │            ATTACKS            │",
            f"│      {k['devices']['totalDevices']:02d}      │      {k['threats']['totalThreats']:02d}      │     {k['risk']['overallRiskLevel']:<8} │               {k['attacks']['totalAttacks']:02d}              │",
            "├──────────────┴──────────────┴──────────────┴───────────────────────────────┤",
            "│                           LIVE NETWORK TOPOLOGY                            │",
            "│                                 Internet                                   │",
            "│                                    │                                       │",
            "│                                 Firewall                                   │",
            "│                                /        \\                                  │",
            "│                              Web         DB                                │",
            "├─────────────────────────────┬──────────────────────────────────────────────┤",
            "│ TRAFFIC                     │ THREAT TIMELINE                              │",
            f"│ Pkts/s: {data['traffic']['currentPacketRate']:6.1f}              │ 10:01 DNS anomaly                            │",
            f"│ Byte/s: {data['traffic']['currentByteRate']/1024:5.1f} KB/s        │ 10:04 Port anomaly                           │",
            f"│ Conns : {data['traffic']['currentActiveConnections']:<3}                 │ 10:07 Traffic spike                          │",
            f"│ TCP: {data['traffic']['protocolBreakdown']['tcp']:4.1f}% │ HTTPS: {data['traffic']['protocolBreakdown']['https']:4.1f}% │ 10:10 Beaconing                              │",
            "├─────────────────────────────┴──────────────────────────────────────────────┤",
            "│ PREDICTIONS                                                                │",
            f"│ Threat Probability: {pred['currentThreatProbability']*100:4.1f}% (Now) ──> {pred['futureThreatProbability']*100:4.1f}% (Future 60s)               │",
            f"│ Category: {pred['predictedCategory']:<24} Confidence: {pred['confidenceScore']*100:4.1f}% │ Risk: {pred['riskLevel']:<8}     │",
            "│ Why?                                                                       │",
            f"│ • {pred['detailedExplanation'][0][:72]} │",
            f"│ • {pred['detailedExplanation'][1][:72]} │",
            "├────────────────────────────────────────────────────────────────────────────┤",
            "│ ATTACK PATH                                                                │",
            f"│ {chain_str:<74} │",
            f"│ Path Risk: {top_path['riskLevel'] if top_path else 'NONE':<8} │ Target: {'CRITICAL' if top_path and top_path['criticalTarget'] else 'LOW':<10} │ Reachability: {top_path['reachability'] if top_path else 'UNKNOWN':<12}     │",
            "└────────────────────────────────────────────────────────────────────────────┘"
        ]
        return "\n".join(lines)

master_dashboard_orchestrator = MasterDashboardUnifiedView()