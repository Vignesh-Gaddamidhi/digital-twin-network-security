from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator
from frontend.topology.three_d_twin_contract import Vector3D, MeshArchetypeEnum
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.topology.security_3d_renderer_engine import security_3d_renderer_engine
from frontend.topology.three_d_scene_engine import three_d_scene_engine
from frontend.topology.three_d_filter_models import (
    AttackPathVisualStatusEnum, ViewModeEnum, VisibilityPresetEnum,
    TopologyFilterCriteria, AttackPath3DVisualDetail, ViewportSyncState, ViewportSwitchResponse
)

class ThreeDNavigationEngine:
    """Manages 3D attack path traversal visuals, non-destructive filtering, and 2D/3D viewport state synchronization."""

    def __init__(self):
        self.sync_state = ViewportSyncState()
        self.cached_attack_paths: Dict[str, AttackPath3DVisualDetail] = {}
        self.sync_attack_paths()

    def sync_attack_paths(self):
        """Builds 3D attack path visual representations from master orchestrator discovery."""
        self.cached_attack_paths.clear()
        cached = getattr(master_attack_path_orchestrator, 'cached_master_analysis', None)
        analysis = cached or master_attack_path_orchestrator.run_master_analysis(
            source_device_id="CLIENT-01",
            target_device_id="DB-01"
        )

        for p in analysis.rankedPaths:
            chain = p.nodeSequence
            edge_ids = []
            vulns = []
            for i in range(len(chain) - 1):
                u, v = chain[i], chain[i + 1]
                matching = [e.edgeId for e in attack_path_graph.edges.values() if e.sourceNode == u and e.destinationNode == v]
                if matching:
                    edge_ids.append(matching[0])

            for nid in chain:
                if nid in attack_path_graph.nodes:
                    vulns.extend(attack_path_graph.nodes[nid].vulnerabilities)

            # Map status
            status_enum = AttackPathVisualStatusEnum.POSSIBLE
            if p.status == "BLOCKED":
                status_enum = AttackPathVisualStatusEnum.BLOCKED
            elif p.status == "ACTIVE":
                status_enum = AttackPathVisualStatusEnum.ACTIVE_SIMULATED
            elif p.status == "UNVERIFIED":
                status_enum = AttackPathVisualStatusEnum.UNVERIFIED

            is_reachable = (p.status in ("POSSIBLE", "ACTIVE", "ACTIVE_SIMULATED"))

            self.cached_attack_paths[p.pathId] = AttackPath3DVisualDetail(
                pathId=p.pathId,
                entryDeviceId=chain[0],
                targetDeviceId=chain[-1],
                traversedNodeSequence=chain,
                traversedEdgeIds=edge_ids,
                riskScore=p.riskScore,
                riskLevel=p.riskLevel,
                likelihoodScore=getattr(p, "likelihoodScore", 0.88),
                impactScore=getattr(p, "impactScore", 0.80),
                status=status_enum,
                vulnerabilitiesExploited=list(dict.fromkeys(vulns)),
                reachability="REACHABLE" if is_reachable else "BLOCKED",
                isHighlighted=(p.pathId == self.sync_state.selectedPathId)
            )

    def select_attack_path_3d(self, path_id: Optional[str]) -> Optional[AttackPath3DVisualDetail]:
        """Highlights path nodes and splines in 3D while dimming unselected elements."""
        self.sync_state.selectedPathId = path_id

        if not path_id or path_id not in self.cached_attack_paths:
            # Unhighlight all
            for p in self.cached_attack_paths.values():
                p.isHighlighted = False
            for d in device_3d_renderer_engine.device_mesh_registry.values():
                d.isHighlighted = False
                d.isVisible = True
            for l in link_3d_renderer_engine.link_registry.values():
                l.isTraversedInAttackPath = False
            three_d_scene_engine.reset_camera()
            return None

        target_path = self.cached_attack_paths[path_id]
        traversed_nodes = set(target_path.traversedNodeSequence)
        traversed_edges = set(target_path.traversedEdgeIds)

        # Highlight devices
        for did, d in device_3d_renderer_engine.device_mesh_registry.items():
            if did in traversed_nodes:
                d.isHighlighted = True
                d.isVisible = True
            else:
                d.isHighlighted = False

        # Highlight links
        for lid, l in link_3d_renderer_engine.link_registry.items():
            l.isTraversedInAttackPath = (lid in traversed_edges)

        # Focus camera on path center
        three_d_scene_engine.focus_path(target_path.traversedNodeSequence)
        target_path.isHighlighted = True
        return target_path

    def apply_topology_filter(self, criteria: TopologyFilterCriteria) -> Dict[str, bool]:
        """Applies non-destructive visual filters without modifying the underlying Twin."""
        self.sync_state.activeFilters = criteria
        visibility_map: Dict[str, bool] = {}
        nodes = attack_path_graph.nodes

        for did, d in device_3d_renderer_engine.device_mesh_registry.items():
            node = nodes.get(did)
            if not node:
                continue

            visible = True

            # Normalized device metadata attributes
            arch_val = (d.archetype.value if hasattr(d.archetype, "value") else str(d.archetype)).upper()
            dev_type = (node.deviceType or "").upper()
            did_upper = did.upper()

            # 1. Device Type Filter
            if criteria.deviceTypeFilter != "ALL":
                f_type = criteria.deviceTypeFilter.upper()
                is_server = (
                    arch_val in ("SERVER", "DATABASE", "DNS")
                    or "SERVER" in dev_type
                    or "DATABASE" in dev_type
                    or "DB" in dev_type
                    or "WEB" in did_upper
                    or "DB" in did_upper
                    or "DNS" in did_upper
                )
                is_client = (
                    arch_val == "CLIENT"
                    or "CLIENT" in dev_type
                    or "CLIENT" in did_upper
                )
                is_router = (
                    arch_val == "ROUTER"
                    or "ROUTER" in dev_type
                    or "ROUTER" in did_upper
                )
                is_firewall = (
                    arch_val == "FIREWALL"
                    or "FIREWALL" in dev_type
                    or "GATEWAY" in dev_type
                    or "FIREWALL" in did_upper
                )

                if f_type == "SERVERS" and not is_server:
                    visible = False
                elif f_type == "CLIENTS" and not is_client:
                    visible = False
                elif f_type == "ROUTERS" and not is_router:
                    visible = False
                elif f_type == "FIREWALLS" and not is_firewall:
                    visible = False
                elif f_type == "DATABASES" and not ("DATABASE" in arch_val or "DB" in did_upper):
                    visible = False
                elif f_type == "DNS" and not ("DNS" in arch_val or "DNS" in did_upper):
                    visible = False

            # 2. Security State Filter
            if visible and criteria.securityStateFilter != "ALL":
                if node.securityState.upper() != criteria.securityStateFilter.upper():
                    visible = False

            # 3. Risk Level Filter
            if visible and criteria.riskLevelFilter != "ALL":
                sec_vis = security_3d_renderer_engine.get_device_security_visual(did)
                r_level = (sec_vis.risk.riskLevel.value if hasattr(sec_vis.risk.riskLevel, "value") else str(sec_vis.risk.riskLevel)).upper()
                if r_level != criteria.riskLevelFilter.upper():
                    visible = False

            # 4. Threat Filter
            if visible and criteria.threatFilter != "ALL":
                sec_vis = security_3d_renderer_engine.get_device_security_visual(did)
                if criteria.threatFilter == "ACTIVE_THREAT" and not sec_vis.hasThreatBeacon:
                    visible = False
                elif criteria.threatFilter == "NO_THREAT" and sec_vis.hasThreatBeacon:
                    visible = False

            # 5. Visibility Preset
            if visible and criteria.visibilityPreset != VisibilityPresetEnum.SHOW_ALL:
                preset = (criteria.visibilityPreset.value if hasattr(criteria.visibilityPreset, "value") else str(criteria.visibilityPreset)).upper()
                if "HIDE_ISOLATED" in preset:
                    if node.securityState.upper() in ("ISOLATED", "QUARANTINED"):
                        visible = False
                elif "SHOW_HIGH_RISK_ONLY" in preset:
                    if node.riskScore < 50.0:
                        visible = False

            d.isVisible = visible
            d.label.isVisible = visible and device_3d_renderer_engine.labels_visible
            visibility_map[did] = visible

        return visibility_map

    def switch_viewport_mode(self, target_mode: ViewModeEnum) -> ViewportSwitchResponse:
        """Seamlessly transitions between 2D and 3D views while preserving active context."""
        prev = self.sync_state.activeViewMode
        self.sync_state.activeViewMode = target_mode
        self.sync_state.lastSwitchedAt = datetime.now(timezone.utc).isoformat()

        # Capture target center coordinates
        coords = {"x": 0.0, "y": 0.0, "z": 0.0}
        if self.sync_state.selectedDeviceId:
            did = self.sync_state.selectedDeviceId
            if did in device_3d_renderer_engine.device_mesh_registry:
                pos = device_3d_renderer_engine.device_mesh_registry[did].position
                coords = {"x": pos.x, "y": pos.y, "z": pos.z}
                if target_mode == ViewModeEnum.VIEW_3D:
                    three_d_scene_engine.focus_device(did)

        preserved = {
            "selectedDeviceId": self.sync_state.selectedDeviceId,
            "selectedPathId": self.sync_state.selectedPathId,
            "timeRange": self.sync_state.timeRange,
            "filters": self.sync_state.activeFilters.model_dump()
        }

        return ViewportSwitchResponse(
            previousMode=prev,
            currentMode=target_mode,
            syncState=self.sync_state,
            targetCoordinates=coords,
            preservedContext=preserved
        )

three_d_navigation_engine = ThreeDNavigationEngine()