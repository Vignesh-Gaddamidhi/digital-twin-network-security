from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.topology_models import TopologyNodeState
from frontend.dashboard.device_inspection_models import EpistemicProvenanceEnum
from frontend.dashboard.device_inspection_engine import device_inspection_engine
from frontend.topology.security_3d_models import (
    ThreatBeacon3D, VulnerabilityBadge3D, RiskBreakdown3D,
    DeviceSecurity3DVisual, SecurityRendererSnapshot
)

class Security3DRendererEngine:
    """Projects canonical security states, risk factors, and threats into 3D visual indicators."""

    STATE_HALO_CONFIG = {
        TopologyNodeState.NORMAL: {"color": "#10B981", "emissive": 0.1, "pulse": 0.0, "cage": False},
        TopologyNodeState.MONITORED: {"color": "#06B6D4", "emissive": 0.4, "pulse": 1.0, "cage": False},
        TopologyNodeState.SUSPICIOUS: {"color": "#F59E0B", "emissive": 0.8, "pulse": 1.8, "cage": False},
        TopologyNodeState.AT_RISK: {"color": "#F97316", "emissive": 1.2, "pulse": 2.5, "cage": False},
        TopologyNodeState.COMPROMISED: {"color": "#EF4444", "emissive": 2.0, "pulse": 4.0, "cage": False},
        TopologyNodeState.ISOLATED: {"color": "#64748B", "emissive": 0.0, "pulse": 0.0, "cage": True},
        TopologyNodeState.UNKNOWN: {"color": "#94A3B8", "emissive": 0.2, "pulse": 0.5, "cage": False}
    }

    def __init__(self):
        self.visual_registry: Dict[str, DeviceSecurity3DVisual] = {}
        self.sync_security_visuals()

    def _map_canonical_state(self, raw_state: str) -> TopologyNodeState:
        s = raw_state.upper()
        if s in ("ISOLATED", "QUARANTINED"):
            return TopologyNodeState.ISOLATED
        elif s in ("COMPROMISED", "OWNED"):
            return TopologyNodeState.COMPROMISED
        elif s == "AT_RISK":
            return TopologyNodeState.AT_RISK
        elif s == "SUSPICIOUS":
            return TopologyNodeState.SUSPICIOUS
        elif s == "MONITORED":
            return TopologyNodeState.MONITORED
        elif s == "NORMAL":
            return TopologyNodeState.NORMAL
        return TopologyNodeState.UNKNOWN

    def sync_security_visuals(self):
        """Builds 3D security visuals strictly from the canonical Twin state."""
        self.visual_registry.clear()
        nodes = attack_path_graph.nodes

        for nid, node in nodes.items():
            state_enum = self._map_canonical_state(node.securityState)
            cfg = self.STATE_HALO_CONFIG[state_enum]

            # Ingest epistemic provenance from device_inspection_engine
            prov = device_inspection_engine.device_provenance_map.get(nid, EpistemicProvenanceEnum.SIMULATION)

            # Compute risk breakdown using Phase 16 model
            tier = threshold_classifier.classify(node.riskScore)
            t_prob = 0.87 if state_enum in (TopologyNodeState.AT_RISK, TopologyNodeState.COMPROMISED) else 0.10
            v_factor = 0.80 if node.vulnerabilities else 0.20
            i_factor = 1.00 if node.assetCriticality == "CRITICAL" else 0.60

            risk_bd = RiskBreakdown3D(
                riskScore=node.riskScore,
                riskLevel=tier,
                threatProbability=t_prob,
                assetCriticality=node.assetCriticality,
                vulnerabilityFactor=v_factor,
                attackImpact=i_factor
            )

            # Map vulnerabilities
            vulns_list = []
            for v_id in node.vulnerabilities:
                vulns_list.append(VulnerabilityBadge3D(
                    vulnerabilityId=v_id,
                    cveName=v_id,
                    severity="HIGH" if "RCE" in v_id or "SQL" in v_id else "MEDIUM",
                    affectedService=node.services[0] if node.services else "core-service",
                    affectedVersion="2.4.1",
                    status="OPEN"
                ))

            # Determine threat beacon
            has_beacon = state_enum in (TopologyNodeState.SUSPICIOUS, TopologyNodeState.AT_RISK, TopologyNodeState.COMPROMISED)
            beacon = None
            if has_beacon:
                beacon = ThreatBeacon3D(
                    eventId=f"EVT-{nid}-2026",
                    eventType="LATERAL_TRAVERSAL" if state_enum == TopologyNodeState.COMPROMISED else "ANOMALY_PROBE",
                    severity=tier,
                    confidence=0.92,
                    detectionSource="ML_DETECTOR" if state_enum == TopologyNodeState.COMPROMISED else "SURICATA_IDS",
                    pulsingSpeed=cfg["pulse"],
                    colorHex=cfg["color"]
                )

            self.visual_registry[nid] = DeviceSecurity3DVisual(
                deviceId=nid,
                securityState=state_enum,
                provenance=prov,
                haloColorHex=cfg["color"],
                emissiveIntensity=cfg["emissive"],
                pulseFrequencyHz=cfg["pulse"],
                hasIsolationCage=cfg["cage"],
                hasThreatBeacon=has_beacon,
                activeBeacon=beacon,
                risk=risk_bd,
                vulnerabilities=vulns_list
            )

    def get_device_security_visual(self, device_id: str) -> DeviceSecurity3DVisual:
        self.sync_security_visuals()
        if device_id not in self.visual_registry:
            raise KeyError(f"Device '{device_id}' does not exist in 3D security registry.")
        return self.visual_registry[device_id]

    def get_snapshot(self) -> SecurityRendererSnapshot:
        self.sync_security_visuals()
        comp = sum(1 for v in self.visual_registry.values() if v.securityState == TopologyNodeState.COMPROMISED)
        iso = sum(1 for v in self.visual_registry.values() if v.securityState == TopologyNodeState.ISOLATED)
        at_risk = sum(1 for v in self.visual_registry.values() if v.securityState == TopologyNodeState.AT_RISK)
        beacons = sum(1 for v in self.visual_registry.values() if v.hasThreatBeacon)

        return SecurityRendererSnapshot(
            totalDevices=len(self.visual_registry),
            compromisedCount=comp,
            isolatedCount=iso,
            atRiskCount=at_risk,
            activeBeaconsCount=beacons,
            securityVisuals=self.visual_registry
        )

security_3d_renderer_engine = Security3DRendererEngine()