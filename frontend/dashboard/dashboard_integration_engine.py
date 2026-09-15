from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta

from frontend.dashboard.dashboard_engine import dashboard_engine
from frontend.dashboard.kpi_summary_engine import kpi_summary_engine
from frontend.traffic.traffic_monitoring_engine import traffic_monitoring_engine
from frontend.threats.threat_timeline_engine import threat_timeline_engine
from frontend.alerts.alert_center_engine import alert_center_engine
from frontend.attacks.attack_path_dashboard_engine import attack_path_dashboard_engine
from frontend.simulations.simulation_control_engine import simulation_control_engine
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from frontend.dashboard.integration_models import (
    ConnectionStateEnum, SubsystemStatusEnum, SubsystemHealthPanel,
    PipelineObservabilityMetrics, GlobalSearchResultItem, UnifiedGlobalSearchResponse,
    RealtimeDashboardFrame
)

class DashboardIntegrationEngine:
    """Central orchestrator for real-time WebSocket frames, observability telemetry, and global indexing."""

    def __init__(self, stale_threshold_sec: float = 5.0):
        self.stale_threshold_sec = stale_threshold_sec
        self.backend_state = ConnectionStateEnum.CONNECTED
        self.last_telemetry_heartbeat = datetime.now(timezone.utc)
        self.global_time_range = "30m"
        self.observability = PipelineObservabilityMetrics()

    def set_connection_state(self, state: ConnectionStateEnum):
        self.backend_state = state

    def pulse_telemetry(self):
        self.last_telemetry_heartbeat = datetime.now(timezone.utc)

    def set_global_time_range(self, time_range: str) -> str:
        self.global_time_range = time_range
        return self.global_time_range

    def get_subsystem_health(self) -> SubsystemHealthPanel:
        now = datetime.now(timezone.utc)
        delta = (now - self.last_telemetry_heartbeat).total_seconds()
        is_stale = delta > self.stale_threshold_sec

        twin_status = SubsystemStatusEnum.SYNCED if attack_path_graph.nodes else SubsystemStatusEnum.DEGRADED
        telemetry_status = SubsystemStatusEnum.STALE if is_stale else SubsystemStatusEnum.ACTIVE
        sim_status = SubsystemStatusEnum.ACTIVE if simulation_control_engine.live_state.executionState.value == "RUNNING" else SubsystemStatusEnum.AVAILABLE

        return SubsystemHealthPanel(
            backendConnection=self.backend_state,
            digitalTwinSync=twin_status,
            telemetryStream=telemetry_status,
            mlInference=SubsystemStatusEnum.AVAILABLE,
            simulationEngine=sim_status,
            lastHeartbeat=self.last_telemetry_heartbeat.isoformat(),
            dataAgeSeconds=round(delta, 2),
            isStale=is_stale
        )

    def generate_realtime_frame(self) -> RealtimeDashboardFrame:
        health = self.get_subsystem_health()
        kpi = kpi_summary_engine.aggregate_live_kpis()
        alerts = alert_center_engine.alerts
        sim = simulation_control_engine.live_state

        return RealtimeDashboardFrame(
            health=health,
            observability=self.observability,
            kpiSummary=kpi.model_dump(),
            activeAlertsCount=len(alerts),
            currentPacketsPerSec=sim.currentPacketsPerSec,
            networkRiskScore=kpi.risk.overallRiskScore
        )

    def global_search(self, query_str: str) -> UnifiedGlobalSearchResponse:
        q = query_str.strip().lower()
        if not q:
            return UnifiedGlobalSearchResponse(query=query_str, totalMatches=0, results=[])

        matches: List[GlobalSearchResultItem] = []

        # 1. Search Devices & IPs
        for nid, node in attack_path_graph.nodes.items():
            ip = node.ipAddresses[0] if node.ipAddresses else ""
            if q in nid.lower() or q in node.hostname.lower() or q in ip.lower():
                matches.append(GlobalSearchResultItem(
                    category="DEVICE",
                    identifier=nid,
                    title=f"Device: {nid} ({node.hostname})",
                    description=f"Zone: {node.zone} | IP: {ip} | Risk: {node.riskScore:.1f}",
                    deepLinkRoute=f"/devices/{nid}",
                    riskScore=node.riskScore
                ))

        # 2. Search Alerts
        for a in alert_center_engine.alerts:
            if q in a.alertId.lower() or q in a.eventType.lower() or q in a.sourceDevice.lower() or q in a.destinationDevice.lower():
                matches.append(GlobalSearchResultItem(
                    category="ALERT",
                    identifier=a.alertId,
                    title=f"Alert: {a.alertId} [{a.eventType}]",
                    description=f"Severity: {a.severity.value} | Flow: {a.sourceDevice} -> {a.destinationDevice}",
                    deepLinkRoute=f"/alerts/{a.alertId}",
                    riskScore=a.riskScore,
                    severity=a.severity.value
                ))

        # 3. Search Attack Paths
        for p in attack_path_dashboard_engine.cached_master_analysis.rankedPaths:
            chain_str = " -> ".join(p.nodeSequence).lower()
            if q in p.pathId.lower() or q in chain_str:
                matches.append(GlobalSearchResultItem(
                    category="ATTACK_PATH",
                    identifier=p.pathId,
                    title=f"Attack Path: {p.pathId} (Rank #{p.rank})",
                    description=f"Route: {' -> '.join(p.nodeSequence)} | Risk: {p.riskScore:.1f}",
                    deepLinkRoute=f"/attacks/{p.pathId}",
                    riskScore=p.riskScore
                ))

        # 4. Search Simulation Scenarios
        for sc in ["lateral_movement_like", "port_scan", "dos_like", "exfiltration_like"]:
            if q in sc:
                matches.append(GlobalSearchResultItem(
                    category="SIMULATION",
                    identifier=sc.upper(),
                    title=f"Scenario: {sc.upper()}",
                    description="Controlled security attack simulation profile",
                    deepLinkRoute=f"/simulations/{sc.upper()}"
                ))

        return UnifiedGlobalSearchResponse(
            query=query_str,
            totalMatches=len(matches),
            results=matches
        )

dashboard_integration_engine = DashboardIntegrationEngine()