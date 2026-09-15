from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from frontend.dashboard.kpi_models import MasterKPISnapshot
from frontend.topology.topology_models import LiveTopologySnapshot
from frontend.traffic.traffic_models import LiveTrafficPanelSnapshot
from frontend.threats.threat_models import ThreatTimelineItem
from frontend.predictions.prediction_models import LivePredictionDetail
from frontend.attacks.attack_path_dashboard_models import AttackPathItemCard
from frontend.alerts.alert_center_models import SecurityAlertItem
from frontend.simulations.simulation_models import SimulationLiveStateView

class MasterDashboardViewSnapshot(BaseModel):
    viewId: str = Field(default_factory=lambda: f"DASHVIEW-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    systemStatus: str = "SYSTEM ACTIVE"
    kpi: MasterKPISnapshot
    simulation: SimulationLiveStateView
    topThreats: List[ThreatTimelineItem]
    topPrediction: LivePredictionDetail
    primaryAttackPath: Optional[AttackPathItemCard] = None

    def render_master_cli_screen(self) -> str:
        d = self.kpi.devices
        t = self.kpi.threats
        r = self.kpi.risk
        a = self.kpi.attacks
        sim = self.simulation
        pred = self.topPrediction
        p_path = self.primaryAttackPath

        path_chain = " ──> ".join(p_path.nodeSequence) if p_path else "NO_ACTIVE_PATH"
        path_info = f"Path Risk: {p_path.riskLevel.value if p_path else 'N/A'} | Target: {p_path.targetNode if p_path else 'N/A'} (CRITICAL) | Reachability: {p_path.reachability if p_path else 'N/A'}"

        # Ensure detailedExplanation has at least 3 items to prevent IndexError
        reasons = list(pred.detailedExplanation) if pred.detailedExplanation else ["Normal telemetry baseline."]
        while len(reasons) < 3:
            reasons.append("No further anomalous deviations detected.")

        lines = [
            "┌────────────────────────────────────────────────────────────────────────────┐",
            f"│ Network Security Digital Twin                              ● {self.systemStatus:<14}│",
            "├──────────────┬──────────────┬──────────────┬───────────────┤",
            "│   DEVICES    │   THREATS    │     RISK     │    ATTACKS    │",
            f"│      {d.totalDevices:02d}      │      {t.totalThreats:02d}      │     {r.overallRiskLevel.value:<8} │       {a.totalAttacks:02d}      │",
            "├──────────────┴──────────────┴──────────────┴───────────────┤",
            "│                 LIVE NETWORK TOPOLOGY                      │",
            "│                               Internet                     │",
            "│                                  │                         │",
            "│                              Firewall                      │",
            "│                              /      \\                      │",
            "│                            Web       DB                    │",
            "├──────────────────────────┬─────────────────────────────────┤",
            "│ TRAFFIC                  │ THREAT TIMELINE                 │",
            f"│ Packet Rate : {sim.currentPacketsPerSec:6.1f} pkts/s│ 10:01 DNS anomaly              │",
            f"│ Byte Rate   : 342.8 KB/s │ 10:04 Port anomaly              │",
            f"│ Connections : 42 active  │ 10:07 Traffic spike             │",
            "│ Protocols   : TCP, HTTPS │ 10:10 Beaconing                 │",
            "├──────────────────────────┴─────────────────────────────────┤",
            "│                    PREDICTIONS                             │",
            f"│ Threat Probability: {pred.futureThreatProbability*100:.0f}%                                    │",
            f"│ Category: {pred.predictedCategory.value:<40}                 │",
            f"│ Confidence: {pred.confidenceScore*100:.0f}%                                                    │",
            f"│ Risk: {pred.riskLevel.value:<40}                            │",
            "│                                                            │",
            "│ Why?                                                       │",
            f"│ • {reasons[0][:68]:<68}│",
            f"│ • {reasons[1][:68]:<68}│",
            f"│ • {reasons[2][:68]:<68}│",
            "├────────────────────────────────────────────────────────────┤",
            "│ ATTACK PATH                                                │",
            f"│ {path_chain:<74} │",
            f"│ {path_info:<74} │",
            "└────────────────────────────────────────────────────────────┘"
        ]
        return "\n".join(lines)