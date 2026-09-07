from typing import List, Dict, Any, Optional
import networkx as nx
from packages.shared_types.src.topology import ConnectionEntity, TopologyValidationResult
from services.twin_engine.src.core.twin_state import DeviceEntity

class TopologyEngine:
    """Constructs and queries the network topology graph."""

    def __init__(self):
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()

    def sync_device(self, device: DeviceEntity):
        self.graph.add_node(
            device.id,
            hostname=device.hostname,
            device_type=device.type,
            role=device.role,
            status=device.current_state.status,
            security_state=device.security_state_model.security_status,
            criticality=device.criticality
        )

    def sync_connection(self, conn: ConnectionEntity):
        self.graph.add_edge(
            conn.source_device,
            conn.destination_device,
            key=conn.connection_id,
            connection_type=conn.connection_type,
            protocol=conn.protocol,
            status=conn.status,
            latency_ms=conn.latency_ms,
            bandwidth_mbps=conn.bandwidth_mbps
        )
        if conn.connection_type == "PHYSICAL_LINK":
            self.graph.add_edge(
                conn.destination_device,
                conn.source_device,
                key=f"{conn.connection_id}-rev",
                connection_type=conn.connection_type,
                protocol=conn.protocol,
                status=conn.status,
                latency_ms=conn.latency_ms,
                bandwidth_mbps=conn.bandwidth_mbps
            )

    def remove_device(self, device_id: str):
        if device_id in self.graph:
            self.graph.remove_node(device_id)

    def remove_connection(self, connection_id: str):
        for u, v, k in list(self.graph.edges(keys=True)):
            if k == connection_id or k == f"{connection_id}-rev":
                self.graph.remove_edge(u, v, key=k)

    def find_shortest_path(self, source_id: str, target_id: str, device_names: Dict[str, str]) -> TopologyValidationResult:
        if source_id not in self.graph or target_id not in self.graph:
            return TopologyValidationResult(is_connected=False)

        undirected = self.graph.to_undirected()
        try:
            path = nx.shortest_path(undirected, source=source_id, target=target_id)
            total_lat = 0.0
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                edge_data = undirected.get_edge_data(u, v)
                total_lat += min(e.get("latency_ms", 1.0) for e in edge_data.values())

            return TopologyValidationResult(
                is_connected=True,
                path_hops=path,
                hop_count=len(path) - 1,
                total_latency_ms=round(total_lat, 2),
                traversed_devices=[device_names.get(p, p) for p in path]
            )
        except nx.NetworkXNoPath:
            return TopologyValidationResult(is_connected=False)

    def find_critical_articulation_points(self) -> List[str]:
        undirected = nx.Graph(self.graph.to_undirected())
        return list(nx.articulation_points(undirected))