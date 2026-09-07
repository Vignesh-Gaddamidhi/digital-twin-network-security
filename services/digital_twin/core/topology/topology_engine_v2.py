from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import networkx as nx

from packages.shared_types.src.network_device import NetworkDeviceModel
from packages.shared_types.src.topology import (
    NetworkConnectionModel, TopologyValidationResult, TopologySummarySnapshotModel, ConnectionTypeEnum
)
from packages.shared_types.src.graph import GraphNodeModel, GraphEdgeModel
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.connections.network_connection_registry import (
    connection_registry, ConnectionNotFoundError
)
from services.digital_twin.core.topology.graph_engine import graph_engine

class TopologyEngine:
    """Coordinates graph-based network representations, pathfinding, and topology metrics."""

    def addDevice(self, device: NetworkDeviceModel) -> NetworkDeviceModel:
        device_registry.createDevice(device)
        graph_engine.addNode(GraphNodeModel(
            id=device.id,
            type=device.type.value,
            label=device.hostname,
            zone=device.networkZone.value,
            state="ACTIVE" if device.currentState == "ONLINE" else "INACTIVE",
            metadata={"criticality": device.riskScore}
        ))
        return device

    def removeDevice(self, device_id: str) -> bool:
        device_registry.deleteDevice(device_id)
        # Purge connections attached to this device
        incident_conns = connection_registry.getAllConnections(device_id=device_id)
        for c in incident_conns:
            connection_registry.deleteConnection(c.id)
        graph_engine.removeNode(device_id)
        return True

    def connectDevices(self, connection: NetworkConnectionModel) -> NetworkConnectionModel:
        connection_registry.createConnection(connection)
        is_bidirectional = connection.connectionType in (ConnectionTypeEnum.PHYSICAL, ConnectionTypeEnum.LOGICAL)
        graph_engine.addEdge(GraphEdgeModel(
            id=connection.id,
            source=connection.sourceDevice,
            target=connection.destinationDevice,
            protocol=connection.protocol.value,
            status=connection.status.value,
            weight=connection.latency,
            metadata={"bandwidth": connection.bandwidth}
        ), is_bidirectional=is_bidirectional)
        return connection

    def disconnectDevices(self, connection_id: str) -> bool:
        connection_registry.deleteConnection(connection_id)
        graph_engine.removeEdge(connection_id)
        return True

    def findNeighbors(self, device_id: str) -> Dict[str, Any]:
        neighbors_res = graph_engine.getNeighbors(device_id)
        return {
            "device_id": device_id,
            "connected_peers": neighbors_res.all_neighbors,
            "inbound": neighbors_res.inbound_neighbors,
            "outbound": neighbors_res.outbound_neighbors
        }

    def findPath(self, source_id: str, destination_id: str) -> TopologyValidationResult:
        if source_id not in graph_engine._nodes or destination_id not in graph_engine._nodes:
            return TopologyValidationResult(is_connected=False)

        undirected = graph_engine._graph.to_undirected()
        try:
            path = nx.shortest_path(undirected, source=source_id, target=destination_id, weight="weight")
            total_latency = 0.0
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                edge_data = undirected.get_edge_data(u, v)
                min_weight = min(e.get("weight", 1.0) for e in edge_data.values())
                total_latency += min_weight

            readable_hops = [
                device_registry.getDevice(d).hostname if device_registry.getDevice(d) else d
                for d in path
            ]
            return TopologyValidationResult(
                is_connected=True,
                path_hops=path,
                hop_count=len(path) - 1,
                total_latency_ms=round(total_latency, 2),
                traversed_devices=readable_hops
            )
        except nx.NetworkXNoPath:
            return TopologyValidationResult(is_connected=False)

    def detectIsolatedDevices(self) -> List[str]:
        """Detects devices with zero active edges or marked offline."""
        isolated = []
        for dev_id in graph_engine._nodes.keys():
            neighbors = graph_engine.getNeighbors(dev_id)
            dev = device_registry.getDevice(dev_id)
            if len(neighbors.all_neighbors) == 0 or (dev and dev.currentState != "ONLINE"):
                isolated.append(dev_id)
        return isolated

    def generateTopologySnapshot(self) -> TopologySummarySnapshotModel:
        all_devices = device_registry.getAllDevices()
        active_count = sum(1 for d in all_devices if d.currentState == "ONLINE")
        inactive_count = len(all_devices) - active_count

        zones = set(d.networkZone.value for d in all_devices)
        edges = connection_registry.getAllConnections()

        return TopologySummarySnapshotModel(
            nodes=len(all_devices),
            edges=len(edges),
            zones=len(zones),
            activeDevices=active_count,
            inactiveDevices=inactive_count,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    def clear(self):
        device_registry.clear()
        connection_registry.clear()
        graph_engine.clear()

topology_engine = TopologyEngine()