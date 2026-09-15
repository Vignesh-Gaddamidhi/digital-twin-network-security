from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.history.risk_state_engine import risk_state_engine
from frontend.dashboard.device_inspection_models import (
    EpistemicProvenanceEnum, DeviceResourceUtilization, DeviceStateTimelineItem,
    LiveDeviceDetailView, DeviceSearchQuery
)

class DeviceInspectionEngine:
    """Manages live device telemetry, security posture inspection, history tracking, and search indexing."""

    def __init__(self):
        self.device_telemetry_cache: Dict[str, DeviceResourceUtilization] = {}
        self.device_state_histories: Dict[str, List[DeviceStateTimelineItem]] = {}
        self.device_provenance_map: Dict[str, EpistemicProvenanceEnum] = {}
        self._seed_default_telemetry()

    def _seed_default_telemetry(self):
        # Baseline telemetries for lab nodes
        self.device_telemetry_cache = {
            "ATTACKER-EXT": DeviceResourceUtilization(
                cpuPercent=85.4, memoryPercent=48.2, networkUtilizationPercent=92.0,
                packetRatePerSec=1850.0, byteRatePerSec=512000.0, activeConnectionCount=12
            ),
            "CLIENT-01": DeviceResourceUtilization(
                cpuPercent=15.2, memoryPercent=34.0, networkUtilizationPercent=8.5,
                packetRatePerSec=45.0, byteRatePerSec=12500.0, activeConnectionCount=4
            ),
            "WEB-01": DeviceResourceUtilization(
                cpuPercent=42.0, memoryPercent=61.0, networkUtilizationPercent=28.0,
                packetRatePerSec=240.0, byteRatePerSec=43008.0, activeConnectionCount=18
            ),
            "DB-01": DeviceResourceUtilization(
                cpuPercent=68.5, memoryPercent=79.4, networkUtilizationPercent=35.0,
                packetRatePerSec=310.0, byteRatePerSec=89600.0, activeConnectionCount=24
            ),
            "DNS-SERVER-01": DeviceResourceUtilization(
                cpuPercent=8.1, memoryPercent=22.5, networkUtilizationPercent=4.0,
                packetRatePerSec=95.0, byteRatePerSec=18400.0, activeConnectionCount=8
            )
        }

        # Seed initial state histories
        now_ts = datetime.now(timezone.utc).isoformat()
        self.device_state_histories = {
            "WEB-01": [
                DeviceStateTimelineItem(timestamp=now_ts, status="NORMAL", riskScore=12.0, triggerEvent="Baseline initialization"),
                DeviceStateTimelineItem(timestamp=now_ts, status="MONITORED", riskScore=28.0, triggerEvent="Connection surge observed"),
                DeviceStateTimelineItem(timestamp=now_ts, status="SUSPICIOUS", riskScore=52.0, triggerEvent="Abnormal port access attempt"),
                DeviceStateTimelineItem(timestamp=now_ts, status="AT_RISK", riskScore=60.8, triggerEvent="Active CVE-2026-WEB-RCE flagged")
            ],
            "CLIENT-01": [
                DeviceStateTimelineItem(timestamp=now_ts, status="NORMAL", riskScore=5.76, triggerEvent="Baseline initialization")
            ],
            "DB-01": [
                DeviceStateTimelineItem(timestamp=now_ts, status="NORMAL", riskScore=25.0, triggerEvent="Baseline initialization"),
                DeviceStateTimelineItem(timestamp=now_ts, status="AT_RISK", riskScore=69.6, triggerEvent="SQL Infiltration Vector Reachable")
            ]
        }

        # Provenance defaults
        for d in ["CLIENT-01", "WEB-01", "DB-01", "DNS-SERVER-01"]:
            self.device_provenance_map[d] = EpistemicProvenanceEnum.SIMULATION
        self.device_provenance_map["ATTACKER-EXT"] = EpistemicProvenanceEnum.REAL_TELEMETRY

    def update_telemetry(self, device_id: str, util: DeviceResourceUtilization):
        self.device_telemetry_cache[device_id] = util

    def record_state_transition(self, device_id: str, new_status: str, risk_score: float, reason: str):
        if device_id not in self.device_state_histories:
            self.device_state_histories[device_id] = []
        self.device_state_histories[device_id].append(DeviceStateTimelineItem(
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=new_status,
            riskScore=risk_score,
            triggerEvent=reason
        ))

    def set_device_provenance(self, device_id: str, prov: EpistemicProvenanceEnum):
        self.device_provenance_map[device_id] = prov

    def get_live_device_detail(self, device_id: str) -> LiveDeviceDetailView:
        node = attack_path_graph.get_node(device_id)
        dev_raw = twin_graph_synchronizer.device_store.get(device_id, {})
        u = self.device_telemetry_cache.get(device_id, DeviceResourceUtilization())
        prov = self.device_provenance_map.get(device_id, EpistemicProvenanceEnum.SIMULATION)
        history = self.device_state_histories.get(device_id, [
            DeviceStateTimelineItem(status=node.securityState, riskScore=node.riskScore, triggerEvent="Initial state")
        ])

        tier = threshold_classifier.classify(node.riskScore)

        return LiveDeviceDetailView(
            deviceId=device_id,
            hostname=node.hostname,
            deviceType=node.deviceType,
            zone=node.zone,
            ipAddresses=node.ipAddresses if node.ipAddresses else [dev_raw.get("ip", "192.168.0.1")],
            macAddress=dev_raw.get("mac", "00:1A:2B:3C:4D:00"),
            os=dev_raw.get("os", "Linux / Windows"),
            provenance=prov,
            utilization=u,
            securityStatus=node.securityState,
            riskScore=node.riskScore,
            riskLevel=tier,
            confidenceScore=0.94 if len(node.vulnerabilities) > 0 else 0.99,
            activeAlertsCount=2 if node.securityState in ("AT_RISK", "COMPROMISED") else 0,
            vulnerabilitiesCount=len(node.vulnerabilities),
            activeVulnerabilities=node.vulnerabilities,
            openPorts=node.exposedPorts,
            services=node.services,
            lastSecurityEvent=history[-1].triggerEvent if history else None,
            stateHistory=history
        )

    def search_devices(self, criteria: DeviceSearchQuery) -> List[LiveDeviceDetailView]:
        results: List[LiveDeviceDetailView] = []
        q = criteria.query.strip().lower()

        for d_id in attack_path_graph.nodes.keys():
            detail = self.get_live_device_detail(d_id)
            
            # String query match across ID, Hostname, IPs, Services
            matches_q = True
            if q:
                match_id = q in detail.deviceId.lower()
                match_host = q in detail.hostname.lower()
                match_ip = any(q in ip.lower() for ip in detail.ipAddresses)
                match_srv = any(q in s.lower() for s in detail.services)
                matches_q = match_id or match_host or match_ip or match_srv

            if not matches_q:
                continue

            # Zone match
            if criteria.zone and detail.zone.upper() != criteria.zone.upper():
                continue

            # Status match
            if criteria.securityStatus and detail.securityStatus.upper() != criteria.securityStatus.upper():
                continue

            # Risk score threshold
            if criteria.minRiskScore is not None and detail.riskScore < criteria.minRiskScore:
                continue

            results.append(detail)

        return results

device_inspection_engine = DeviceInspectionEngine()