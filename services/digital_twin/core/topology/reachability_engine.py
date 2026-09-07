from collections import deque
from typing import List, Optional, Dict, Any, Tuple
import networkx as nx

from packages.shared_types.src.reachability import ReachabilityEvaluationResult, PathHopDetail
from packages.shared_types.src.firewall import FirewallActionEnum
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine

class ReachabilityEngine:
    """Calculates graph traversal paths and security-constrained reachability."""

    @staticmethod
    def getNeighbors(device_id: str) -> List[str]:
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")
        res = graph_engine.getNeighbors(device_id)
        return res.all_neighbors

    @staticmethod
    def findPath(source_id: str, destination_id: str) -> Optional[List[str]]:
        """Classic unweighted Breadth-First Search (BFS) to find the minimum-hop path."""
        if source_id not in graph_engine._nodes or destination_id not in graph_engine._nodes:
            return None

        if source_id == destination_id:
            return [source_id]

        queue = deque([[source_id]])
        visited = {source_id}
        undirected = graph_engine._graph.to_undirected()

        while queue:
            current_path = queue.popleft()
            last_node = current_path[-1]

            for neighbor in undirected.neighbors(last_node):
                if neighbor == destination_id:
                    return current_path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(current_path + [neighbor])
        return None

    @staticmethod
    def getShortestPath(source_id: str, destination_id: str, weight_metric: str = "weight") -> Tuple[Optional[List[str]], float]:
        """Calculates the lowest-cost path using Dijkstra's algorithm."""
        if source_id not in graph_engine._nodes or destination_id not in graph_engine._nodes:
            return None, 0.0

        undirected = graph_engine._graph.to_undirected()
        try:
            path = nx.shortest_path(undirected, source=source_id, target=destination_id, weight=weight_metric)
            cost = nx.shortest_path_length(undirected, source=source_id, target=destination_id, weight=weight_metric)
            return path, float(cost)
        except nx.NetworkXNoPath:
            return None, 0.0

    @classmethod
    def isReachable(
        cls,
        source_id: str,
        destination_id: str,
        protocol: str = "TCP",
        destination_port: Optional[int] = None
    ) -> ReachabilityEvaluationResult:
        """Evaluates whether traffic can traverse from source to destination under all operational and firewall constraints."""
        src_dev = device_registry.getDevice(source_id)
        dst_dev = device_registry.getDevice(destination_id)

        if not src_dev:
            raise DeviceNotFoundError(f"Source device '{source_id}' not found.")
        if not dst_dev:
            raise DeviceNotFoundError(f"Destination device '{destination_id}' not found.")

        # 1. Base Endpoint Health Check
        if src_dev.currentState != "ONLINE":
            return ReachabilityEvaluationResult(
                source_device=source_id, destination_device=destination_id,
                is_reachable=False, protocol=protocol, destination_port=destination_port,
                hop_count=0, path=[], hops_detail=[], total_latency_ms=0.0,
                blocking_reason=f"Source device '{src_dev.hostname}' is {src_dev.currentState}."
            )

        if dst_dev.currentState != "ONLINE":
            return ReachabilityEvaluationResult(
                source_device=source_id, destination_device=destination_id,
                is_reachable=False, protocol=protocol, destination_port=destination_port,
                hop_count=0, path=[], hops_detail=[], total_latency_ms=0.0,
                blocking_reason=f"Destination device '{dst_dev.hostname}' is {dst_dev.currentState}."
            )

        # 2. Port Listening Check on Destination
        if destination_port is not None and destination_port not in dst_dev.ports:
            return ReachabilityEvaluationResult(
                source_device=source_id, destination_device=destination_id,
                is_reachable=False, protocol=protocol, destination_port=destination_port,
                hop_count=0, path=[], hops_detail=[], total_latency_ms=0.0,
                blocking_reason=f"Port {destination_port} is not listening on '{dst_dev.hostname}'."
            )

        # 3. Path Discovery (BFS)
        path = cls.findPath(source_id, destination_id)
        if not path:
            return ReachabilityEvaluationResult(
                source_device=source_id, destination_device=destination_id,
                is_reachable=False, protocol=protocol, destination_port=destination_port,
                hop_count=0, path=[], hops_detail=[], total_latency_ms=0.0,
                blocking_reason="No topological path exists in graph."
            )

        # 4. Multi-Hop Step-by-Step Validation
        hops_detail: List[PathHopDetail] = []
        total_latency = 0.0

        for i, node_id in enumerate(path):
            node_dev = device_registry.getDevice(node_id)
            node_zone = firewall_engine.getDeviceZone(node_id).value

            # Check intermediate forwarder operational status
            if node_dev.currentState != "ONLINE":
                return ReachabilityEvaluationResult(
                    source_device=source_id, destination_device=destination_id,
                    is_reachable=False, protocol=protocol, destination_port=destination_port,
                    hop_count=len(path) - 1, path=path, hops_detail=hops_detail, total_latency_ms=total_latency,
                    blocking_reason=f"Intermediate hop '{node_dev.hostname}' is {node_dev.currentState}."
                )

            egress_conn_id = None
            if i < len(path) - 1:
                next_node_id = path[i + 1]
                # Find connection between node_id and next_node_id
                conns = connection_registry.getAllConnections(device_id=node_id)
                active_conn = next(
                    (c for c in conns if (c.sourceDevice == node_id and c.destinationDevice == next_node_id) or
                                         (c.sourceDevice == next_node_id and c.destinationDevice == node_id)),
                    None
                )
                if active_conn:
                    if active_conn.status.value != "ACTIVE":
                        return ReachabilityEvaluationResult(
                            source_device=source_id, destination_device=destination_id,
                            is_reachable=False, protocol=protocol, destination_port=destination_port,
                            hop_count=len(path) - 1, path=path, hops_detail=hops_detail, total_latency_ms=total_latency,
                            blocking_reason=f"Connection '{active_conn.id}' is {active_conn.status.value}."
                        )
                    egress_conn_id = active_conn.id
                    total_latency += active_conn.latency

            hops_detail.append(PathHopDetail(
                hop_number=i + 1,
                device_id=node_id,
                hostname=node_dev.hostname,
                device_type=node_dev.type.value,
                zone=node_zone,
                state=node_dev.currentState,
                egress_connection_id=egress_conn_id,
                firewall_decision="PERMITTED"
            ))

        # 5. Security Boundary & Firewall Evaluation
        firewall_check = firewall_engine.inspectTraffic(
            source_device_id=source_id,
            destination_device_id=destination_id,
            protocol=protocol,
            destination_port=destination_port
        )

        if firewall_check.decision != FirewallActionEnum.ALLOW:
            return ReachabilityEvaluationResult(
                source_device=source_id, destination_device=destination_id,
                is_reachable=False, protocol=protocol, destination_port=destination_port,
                hop_count=len(path) - 1, path=path, hops_detail=hops_detail, total_latency_ms=total_latency,
                blocking_reason=f"Firewall policy DENIED: {firewall_check.explanation}"
            )

        return ReachabilityEvaluationResult(
            source_device=source_id, destination_device=destination_id,
            is_reachable=True, protocol=protocol, destination_port=destination_port,
            hop_count=len(path) - 1, path=path, hops_detail=hops_detail, total_latency_ms=round(total_latency, 2),
            blocking_reason=None
        )

reachability_engine = ReachabilityEngine()