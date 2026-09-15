from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.attack_path.graph.graph_models import NodeTypeEnum
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.nodes.entry_point_engine import entry_point_engine
from frontend.topology.topology_models import (
    TopologyNodeState, CanvasCoordinates, TopologyNodeVisual, TopologyEdgeVisual,
    SubnetZoneBoundary, ViewportTransform, LiveTopologySnapshot, NodeDetailDrawer
)

class TopologyCanvasEngine:
    """Computes layout coordinates, viewport transforms, edge flows, and side-drawer inspection."""

    ZONE_CONFIG = {
        "INTERNET": {"cidr": "0.0.0.0/0", "color": "#E0E7FF", "y_offset": 50.0},
        "DMZ": {"cidr": "192.168.20.0/24", "color": "#FEF3C7", "y_offset": 220.0},
        "INTERNAL": {"cidr": "192.168.10.0/24", "color": "#D1FAE5", "y_offset": 400.0},
        "DATABASE": {"cidr": "192.168.30.0/24", "color": "#FEE2E2", "y_offset": 580.0},
        "INFRA": {"cidr": "192.168.1.0/24", "color": "#E5E7EB", "y_offset": 400.0}
    }

    def __init__(self):
        self.viewport = ViewportTransform()
        self.selected_node_id: Optional[str] = None
        self.active_filter: str = "ALL"

    def zoom_in(self, factor: float = 1.2) -> ViewportTransform:
        self.viewport.zoomLevel = min(self.viewport.maxZoom, round(self.viewport.zoomLevel * factor, 2))
        return self.viewport

    def zoom_out(self, factor: float = 0.8) -> ViewportTransform:
        self.viewport.zoomLevel = max(self.viewport.minZoom, round(self.viewport.zoomLevel * factor, 2))
        return self.viewport

    def reset_view(self) -> ViewportTransform:
        self.viewport = ViewportTransform(zoomLevel=1.0, panX=0.0, panY=0.0)
        return self.viewport

    def pan(self, delta_x: float, delta_y: float) -> ViewportTransform:
        self.viewport.panX = round(self.viewport.panX + delta_x, 2)
        self.viewport.panY = round(self.viewport.panY + delta_y, 2)
        return self.viewport

    def fit_to_screen(self, node_count: int) -> ViewportTransform:
        if node_count > 20:
            self.viewport.zoomLevel = 0.75
        elif node_count > 50:
            self.viewport.zoomLevel = 0.50
        else:
            self.viewport.zoomLevel = 1.0
        self.viewport.panX = 0.0
        self.viewport.panY = 0.0
        return self.viewport

    def _map_security_state(self, raw_state: str) -> TopologyNodeState:
        st = raw_state.upper()
        if st in TopologyNodeState.__members__:
            return TopologyNodeState[st]
        elif st in ("QUARANTINED", "ISOLATED"):
            return TopologyNodeState.ISOLATED
        elif st == "AT_RISK":
            return TopologyNodeState.AT_RISK
        elif st == "COMPROMISED":
            return TopologyNodeState.COMPROMISED
        return TopologyNodeState.NORMAL

    def generate_live_topology(self, filter_name: str = "ALL") -> LiveTopologySnapshot:
        self.active_filter = filter_name.upper()
        nodes_visual: List[TopologyNodeVisual] = []
        edges_visual: List[TopologyEdgeVisual] = []

        # Coordinate positioning registry
        zone_node_indices: Dict[str, int] = {}

        # 1. Process Nodes
        for nid, n in attack_path_graph.nodes.items():
            z = n.zone.upper()
            idx = zone_node_indices.get(z, 0)
            zone_node_indices[z] = idx + 1

            # Determine layout coordinates
            base_y = self.ZONE_CONFIG.get(z, {"y_offset": 300.0})["y_offset"]
            x_pos = 150.0 + (idx * 220.0)
            y_pos = base_y

            # Retrieve telemetry and risk
            sec_state = self._map_security_state(n.securityState)
            t_prob = 0.87 if sec_state in (TopologyNodeState.AT_RISK, TopologyNodeState.COMPROMISED) else 0.08
            tier = threshold_classifier.classify(n.riskScore)

            dev_raw = twin_graph_synchronizer.device_store.get(nid, {})

            nv = TopologyNodeVisual(
                id=nid,
                deviceId=nid,
                hostname=n.hostname,
                label=nid,
                nodeType=n.nodeType.value if hasattr(n.nodeType, "value") else str(n.nodeType),
                zone=z,
                ipAddress=n.ipAddresses[0] if n.ipAddresses else "192.168.0.1",
                macAddress=dev_raw.get("mac", "00:1A:2B:3C:4D:00"),
                os=dev_raw.get("os", "Linux 6.x"),
                securityState=sec_state,
                riskScore=n.riskScore,
                riskLevel=tier,
                threatProbability=t_prob,
                openPorts=n.exposedPorts,
                services=n.services,
                vulnerabilitiesCount=len(n.vulnerabilities),
                activeVulnerabilities=n.vulnerabilities,
                position=CanvasCoordinates(x=x_pos, y=y_pos),
                isTarget=(n.assetCriticality == "CRITICAL"),
                isAttacker=(n.nodeType == NodeTypeEnum.ATTACKER)
            )

            # Apply Filter
            if self._node_matches_filter(nv, self.active_filter):
                nodes_visual.append(nv)

        visible_node_ids = {nv.id for nv in nodes_visual}

        # 2. Process Edges
        for eid, e in attack_path_graph.edges.items():
            if e.sourceNode in visible_node_ids and e.destinationNode in visible_node_ids:
                reach = "REACHABLE" if e.reachable else "BLOCKED"
                status = "ACTIVE" if e.reachable else "BLOCKED"
                ev = TopologyEdgeVisual(
                    id=eid,
                    source=e.sourceNode,
                    target=e.destinationNode,
                    protocol=e.protocol,
                    destinationPort=e.destinationPort,
                    service=e.service,
                    status=status,
                    reachability=reach,
                    hasActiveTraffic=e.reachable,
                    trafficRateBps=4096.0 if e.reachable else 0.0,
                    securityControl=e.securityControl
                )
                edges_visual.append(ev)

        # 3. Process Subnet Zones Boundaries
        zones_visual: List[SubnetZoneBoundary] = []
        for zk, zcfg in self.ZONE_CONFIG.items():
            zones_visual.append(SubnetZoneBoundary(
                zoneId=zk,
                name=f"{zk} Subnet",
                cidr=zcfg["cidr"],
                zoneType=zk,
                colorTheme=zcfg["color"],
                bounds={"x": 50.0, "y": zcfg["y_offset"] - 40.0, "width": 800.0, "height": 130.0}
            ))

        return LiveTopologySnapshot(
            nodes=nodes_visual,
            edges=edges_visual,
            zones=zones_visual,
            viewport=self.viewport,
            totalNodes=len(nodes_visual),
            totalEdges=len(edges_visual),
            activeTrafficConnections=sum(1 for ev in edges_visual if ev.hasActiveTraffic)
        )

    def _node_matches_filter(self, node: TopologyNodeVisual, filter_str: str) -> bool:
        if filter_str in ("ALL", ""):
            return True
        elif filter_str == "SERVERS":
            return "SERVER" in node.nodeType.upper() or "DATABASE" in node.nodeType.upper()
        elif filter_str == "CLIENTS":
            return "CLIENT" in node.nodeType.upper()
        elif filter_str == "NETWORK_DEVICES":
            return node.nodeType.upper() in ("ROUTER", "FIREWALL", "SWITCH")
        elif filter_str == "CRITICAL_ASSETS":
            return node.isTarget or node.riskLevel == RiskLevelTier.CRITICAL
        elif filter_str == "AT_RISK":
            return node.securityState == TopologyNodeState.AT_RISK
        elif filter_str == "COMPROMISED":
            return node.securityState == TopologyNodeState.COMPROMISED
        elif filter_str == "ISOLATED":
            return node.securityState == TopologyNodeState.ISOLATED
        return True

    def get_node_detail_drawer(self, device_id: str) -> NodeDetailDrawer:
        self.selected_node_id = device_id
        node = attack_path_graph.get_node(device_id)
        dev_raw = twin_graph_synchronizer.device_store.get(device_id, {})
        tier = threshold_classifier.classify(node.riskScore)

        # Find peers connected
        peers = set()
        for e in attack_path_graph.edges.values():
            if e.sourceNode == device_id:
                peers.add(e.destinationNode)
            elif e.destinationNode == device_id:
                peers.add(e.sourceNode)

        return NodeDetailDrawer(
            deviceId=device_id,
            hostname=node.hostname,
            zone=node.zone,
            ipAddress=node.ipAddresses[0] if node.ipAddresses else "192.168.0.1",
            macAddress=dev_raw.get("mac", "00:1A:2B:3C:4D:00"),
            os=dev_raw.get("os", "Linux / Windows"),
            deviceType=node.deviceType,
            securityState=self._map_security_state(node.securityState),
            riskScore=node.riskScore,
            riskLevel=tier,
            threatProbability=0.87 if node.securityState in ("AT_RISK", "COMPROMISED") else 0.08,
            openPorts=node.exposedPorts,
            services=node.services,
            vulnerabilitiesCount=len(node.vulnerabilities),
            vulnerabilities=node.vulnerabilities,
            activeConnectionsCount=len(peers),
            connectedPeers=list(peers),
            isolationStatus=(node.securityState in ("QUARANTINED", "ISOLATED"))
        )

    def render_cli_canvas(self, snapshot: LiveTopologySnapshot) -> str:
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                     LIVE NETWORK TOPOLOGY CANVAS                             ║",
            f"║ Viewport: Zoom={snapshot.viewport.zoomLevel:.1f}x Pan=({snapshot.viewport.panX:.0f}, {snapshot.viewport.panY:.0f}) Filter=[{self.active_filter:<12}] Nodes: {snapshot.totalNodes:02d} Edges: {snapshot.totalEdges:02d}  ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣"
        ]
        # Draw zones and nodes
        for z in ["INTERNET", "DMZ", "INTERNAL", "DATABASE"]:
            z_nodes = [n for n in snapshot.nodes if n.zone == z]
            node_labels = "  ".join([f"[{n.id}:{n.securityState.value[:4]}]" for n in z_nodes]) or "None"
            lines.append(f"║ {z:<10} │ {node_labels:<62} ║")
        lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
        lines.append("║ ACTIVE DIRECTED FLOWS:                                                       ║")
        for e in snapshot.edges[:4]:
            flow_sym = "──→" if e.reachability == "REACHABLE" else "─X─"
            lines.append(f"║ * {e.source} {flow_sym} {e.target} ({e.protocol}/{e.destinationPort}) [{e.reachability:<9}] ({e.trafficRateBps:4.0f} bps)  ║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)

topology_canvas_engine = TopologyCanvasEngine()