from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from frontend.topology.three_d_twin_contract import Vector3D
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_models import (
    LinkStateEnum, TrafficFlowDirectionEnum, TrafficProtocolType,
    TrafficParticleState, NetworkLink3D, LinkRendererSnapshot
)

class Link3DRendererEngine:
    """Calculates 3D link curves, animates bounded traffic particles, and coordinates link states."""

    PROTOCOL_COLORS = {
        TrafficProtocolType.TCP: "#3B82F6",
        TrafficProtocolType.UDP: "#10B981",
        TrafficProtocolType.ICMP: "#F59E0B",
        TrafficProtocolType.HTTP: "#06B6D4",
        TrafficProtocolType.HTTPS: "#6366F1",
        TrafficProtocolType.DNS: "#EC4899",
        TrafficProtocolType.SSH: "#F97316"
    }

    PROTOCOL_SPEEDS = {
        TrafficProtocolType.TCP: 0.020,
        TrafficProtocolType.UDP: 0.028,
        TrafficProtocolType.ICMP: 0.015,
        TrafficProtocolType.HTTP: 0.022,
        TrafficProtocolType.HTTPS: 0.022,
        TrafficProtocolType.DNS: 0.035,
        TrafficProtocolType.SSH: 0.018
    }

    def __init__(self, max_particle_capacity: int = 500):
        self.max_particle_capacity = max_particle_capacity
        self.link_registry: Dict[str, NetworkLink3D] = {}
        self.sync_links_from_twin()

    def sync_links_from_twin(self):
        """Constructs 3D link splines from attack_path_graph.edges without creating duplicate data."""
        self.link_registry.clear()
        edges = attack_path_graph.edges
        device_meshes = device_3d_renderer_engine.device_mesh_registry

        for eid, edge in edges.items():
            u, v = edge.sourceNode, edge.destinationNode
            if u not in device_meshes or v not in device_meshes:
                continue

            pos_u = device_meshes[u].position
            pos_v = device_meshes[v].position

            # Calculate arc mid-point with an elevation offset
            mid_x = (pos_u.x + pos_v.x) / 2.0
            mid_z = (pos_u.z + pos_v.z) / 2.0
            mid_y = max(pos_u.y, pos_v.y) + 12.0  # Parabolic arc lift
            mid_pos = Vector3D(x=round(mid_x, 1), y=round(mid_y, 1), z=round(mid_z, 1))

            proto_mapped = self._map_protocol(edge.protocol, edge.destinationPort)
            link_status = LinkStateEnum.ACTIVE if edge.reachable else LinkStateEnum.BLOCKED

            self.link_registry[eid] = NetworkLink3D(
                linkId=eid,
                connectionId=f"CONN-{eid}",
                sourceDeviceId=u,
                destinationDeviceId=v,
                protocol=proto_mapped,
                sourcePort=getattr(edge, "sourcePort", None) or 49152,
                destinationPort=edge.destinationPort,
                interfaceName="eth0",
                status=link_status,
                sourcePos=pos_u,
                destinationPos=pos_v,
                midArcPos=mid_pos,
                isReachable=edge.reachable,
                activeParticles=[]
            )

    def _map_protocol(self, raw_proto: str, port: int) -> TrafficProtocolType:
        if port == 443:
            return TrafficProtocolType.HTTPS
        elif port == 80:
            return TrafficProtocolType.HTTP
        elif port == 53:
            return TrafficProtocolType.DNS
        elif port == 22:
            return TrafficProtocolType.SSH
        
        pu = raw_proto.upper()
        if "UDP" in pu:
            return TrafficProtocolType.UDP
        elif "ICMP" in pu:
            return TrafficProtocolType.ICMP
        return TrafficProtocolType.TCP

    def inject_traffic_flow(
        self,
        link_id: str,
        protocol: Optional[TrafficProtocolType] = None,
        direction: TrafficFlowDirectionEnum = TrafficFlowDirectionEnum.FORWARD,
        bytes_count: int = 1024
    ) -> Optional[TrafficParticleState]:
        """Spawns an animated traffic flow particle adhering to total particle buffer limits."""
        if link_id not in self.link_registry:
            return None

        link = self.link_registry[link_id]
        if link.status == LinkStateEnum.BLOCKED or not link.isReachable:
            return None

        current_total = sum(len(l.activeParticles) for l in self.link_registry.values())
        if current_total >= self.max_particle_capacity:
            # Capacity reached - drop packet to maintain rendering framerate
            return None

        proto = protocol or link.protocol
        color = self.PROTOCOL_COLORS.get(proto, "#3B82F6")
        speed = self.PROTOCOL_SPEEDS.get(proto, 0.02)

        start_t = 0.0 if direction == TrafficFlowDirectionEnum.FORWARD else 1.0

        p = TrafficParticleState(
            linkId=link_id,
            protocol=proto,
            direction=direction,
            progressT=start_t,
            speed=speed,
            colorHex=color,
            bytesTransferred=bytes_count
        )
        link.activeParticles.append(p)
        return p

    def step_particle_simulation(self) -> int:
        """Advances particle progress along link curves and prunes completed flows."""
        recycled_count = 0
        for link in self.link_registry.values():
            active: List[TrafficParticleState] = []
            for p in link.activeParticles:
                if p.direction == TrafficFlowDirectionEnum.FORWARD:
                    p.progressT += p.speed
                    if p.progressT < 1.0:
                        active.append(p)
                    else:
                        recycled_count += 1
                else:
                    p.progressT -= p.speed
                    if p.progressT > 0.0:
                        active.append(p)
                    else:
                        recycled_count += 1
            link.activeParticles = active
        return recycled_count

    def update_link_status(self, link_id: str, new_status: LinkStateEnum):
        if link_id in self.link_registry:
            link = self.link_registry[link_id]
            link.status = new_status
            link.isReachable = (new_status == LinkStateEnum.ACTIVE)
            if not link.isReachable:
                link.activeParticles.clear()

    def clear_all_traffic(self):
        """Cleans up all active traffic particle allocations."""
        for link in self.link_registry.values():
            link.activeParticles.clear()

    def get_snapshot(self) -> LinkRendererSnapshot:
        total_p = sum(len(l.activeParticles) for l in self.link_registry.values())
        active_l = sum(1 for l in self.link_registry.values() if l.status == LinkStateEnum.ACTIVE)
        blocked_l = sum(1 for l in self.link_registry.values() if l.status == LinkStateEnum.BLOCKED)

        return LinkRendererSnapshot(
            totalLinks=len(self.link_registry),
            activeLinksCount=active_l,
            blockedLinksCount=blocked_l,
            totalActiveParticles=total_p,
            maxParticleCapacity=self.max_particle_capacity,
            links=self.link_registry
        )

link_3d_renderer_engine = Link3DRendererEngine()