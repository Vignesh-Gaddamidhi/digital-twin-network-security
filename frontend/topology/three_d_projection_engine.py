from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator
from frontend.topology.three_d_twin_contract import (
    MeshArchetypeEnum, Vector3D, CanonicalTwinDevice, DeviceVisual3DState,
    LinkVisual3DState, Unified3DTwinState, DeviceTo3DMapper
)

class ThreeDProjectionEngine:
    """Extracts backend Twin state and constructs the 3D WebGL projection contract."""

    def __init__(self):
        self.selected_device_id: Optional[str] = None
        self.highlighted_path_id: Optional[str] = None

    def build_3d_twin_state(self) -> Unified3DTwinState:
        canonical_devices: List[CanonicalTwinDevice] = []
        visual_states: Dict[str, DeviceVisual3DState] = {}
        links_3d: List[LinkVisual3DState] = []

        # 1. Group nodes by zone for coordinate calculations
        nodes = attack_path_graph.nodes
        zones: Dict[str, List[str]] = {}
        for nid, node in nodes.items():
            z = node.zone.upper()
            zones.setdefault(z, []).append(nid)

        # 2. Build Canonical Devices and 3D Visual States
        for z, node_ids in zones.items():
            total_in_zone = len(node_ids)
            for idx, nid in enumerate(node_ids):
                node = nodes[nid]
                dev_raw = twin_graph_synchronizer.device_store.get(nid, {})
                tier = threshold_classifier.classify(node.riskScore)
                is_iso = node.securityState in ("QUARANTINED", "ISOLATED")
                is_crit = (node.assetCriticality in ("HIGH", "CRITICAL") or "DB" in nid)
                t_prob = 0.87 if node.securityState in ("AT_RISK", "COMPROMISED") else 0.08

                # Canonical Data Object
                canon = CanonicalTwinDevice(
                    deviceId=nid,
                    hostname=node.hostname,
                    deviceType=node.deviceType,
                    zone=z,
                    ipAddresses=node.ipAddresses if node.ipAddresses else [dev_raw.get("ip", "192.168.0.1")],
                    macAddress=dev_raw.get("mac", "00:1A:2B:3C:4D:00"),
                    os=dev_raw.get("os", "Linux"),
                    services=node.services,
                    openPorts=node.exposedPorts,
                    securityState=node.securityState,
                    riskScore=node.riskScore,
                    riskLevel=tier,
                    threatProbability=t_prob,
                    vulnerabilities=node.vulnerabilities,
                    isCriticalAsset=is_crit,
                    isIsolated=is_iso
                )
                canonical_devices.append(canon)

                # Visual 3D State
                archetype = DeviceTo3DMapper.map_archetype(node.deviceType)
                pos = DeviceTo3DMapper.compute_initial_position(z, idx, total_in_zone)
                base_color = DeviceTo3DMapper.ARCHETYPE_COLORS.get(archetype, "#9CA3AF")

                # Emissive coloring based on security state
                emissive = "#000000"
                if node.securityState == "COMPROMISED":
                    emissive = "#EF4444"
                elif node.securityState == "AT_RISK":
                    emissive = "#F59E0B"
                elif is_iso:
                    emissive = "#6B7280"

                vis = DeviceVisual3DState(
                    deviceId=nid,
                    archetype=archetype,
                    position=pos,
                    colorHex=base_color,
                    emissiveHex=emissive,
                    isSelected=(nid == self.selected_device_id),
                    isHighlighted=False,
                    isVisible=True,
                    particlePulseRate=3.0 if node.securityState in ("AT_RISK", "COMPROMISED") else 1.0
                )
                visual_states[nid] = vis

        # 3. Build 3D Link Curves
        for eid, edge in attack_path_graph.edges.items():
            u, v = edge.sourceNode, edge.destinationNode
            if u in visual_states and v in visual_states:
                pos_u = visual_states[u].position
                pos_v = visual_states[v].position
                link = LinkVisual3DState(
                    linkId=eid,
                    sourceDeviceId=u,
                    targetDeviceId=v,
                    sourcePos=pos_u,
                    targetPos=pos_v,
                    protocol=edge.protocol,
                    isReachable=edge.reachable,
                    isBlocked=(not edge.reachable or edge.status == "BLOCKED"),
                    isTraversedInAttackPath=False,
                    trafficParticleCount=25 if edge.reachable else 0,
                    colorHex="#10B981" if edge.reachable else "#EF4444"
                )
                links_3d.append(link)

        return Unified3DTwinState(
            devices=canonical_devices,
            visualStates=visual_states,
            links=links_3d,
            totalDevices=len(canonical_devices),
            totalLinks=len(links_3d)
        )

three_d_projection_engine = ThreeDProjectionEngine()