from collections import deque
from typing import List, Optional, Dict, Any, Tuple
import networkx as nx

from packages.shared_types.src.reachability import ReachabilityEvaluationResult, PathHopDetail
from packages.shared_types.src.firewall import FirewallActionEnum
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.twin_engine.src.core.twin_state import twin_engine

class ReachabilityEngine:
    """Calculates graph traversal paths and security-constrained reachability."""

    @staticmethod
    def _resolve_device(device_id: str) -> Any:
        dev = device_registry.getDevice(device_id)
        if dev:
            return dev
        return twin_engine.node_registry.get(device_id)

    @classmethod
    def getNeighbors(cls, device_id: str) -> List[str]:
        dev = cls._resolve_device(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' not found.")
        res = graph_engine.getNeighbors(device_id)
        return res.all_neighbors

    @staticmethod
    def _is_connection_active(conn: Any) -> bool:
        if not conn:
            return False
        status_val = conn.status.value if hasattr(conn.status, "value") else str(conn.status)
        return status_val.upper() == "ACTIVE"

    @classmethod
    def findPath(cls, source_id: str, destination_id: str, respect_link_status: bool = False) -> Optional[List[str]]:
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
                if respect_link_status:
                    conns = connection_registry.getAllConnections(device_id=last_node)
                    conn = next(
                        (c for c in conns if (c.sourceDevice == last_node and c.destinationDevice == neighbor) or 
                                             (c.sourceDevice == neighbor and c.destinationDevice == last_node)),
                        None
                    )
                    if conn and not cls._is_connection_active(conn):
                        continue

                if neighbor == destination_id:
                    return current_path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(current_path + [neighbor])
        return None

    @staticmethod
    def getShortestPath(source_id: str, destination_id: str, weight_metric: str = "weight") -> Tuple[Optional[List[str]], float]:
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
        src_dev = cls._resolve_device(source_id)
        dst_dev = cls._resolve_device(destination_id)

        if not src_dev:
            raise DeviceNotFoundError(f"Source device '{source_id}' not found.")
        if not dst_dev:
            raise DeviceNotFoundError(f"Destination device '{destination_id}' not found.")

        src_status = getattr(src_dev, "currentState", getattr(src_dev, "status", "ONLINE"))
        if hasattr(src_status, "value"):
            src_status = src_status.value
        if src_status not in ("ONLINE", "HEALTHY"):
            return ReachabilityEvaluationResult(
                source_device=source_id, destination_device=destination_id,
                is_reachable=False, protocol=protocol, destination_port=destination_port,
                hop_count=0, path=[], hops_detail=[], total_latency_ms=0.0,
                blocking_reason=f"Source device '{getattr(src_dev, 'hostname', source_id)}' is {src_status}."
            )

        dst_status = getattr(dst_dev, "currentState", getattr(dst_dev, "status", "ONLINE"))
        if hasattr(dst_status, "value"):
            dst_status = dst_status.value
        if dst_status not in ("ONLINE", "HEALTHY"):
            return ReachabilityEvaluationResult(
                source_device=source_id, destination_device=destination_id,
                is_reachable=False, protocol=protocol, destination_port=destination_port,
                hop_count=0, path=[], hops_detail=[], total_latency_ms=0.0,
                blocking_reason=f"Destination device '{getattr(dst_dev, 'hostname', destination_id)}' is {dst_status}."
            )

        dst_ports = getattr(dst_dev, "ports", getattr(dst_dev, "open_ports", []))
        if destination_port is not None and destination_port not in dst_ports:
            detailed_ports = getattr(dst_dev, "detailed_ports", [])
            port_match = any(getattr(p, "port_number", p) == destination_port for p in detailed_ports)
            if not port_match and destination_port != 0:
                return ReachabilityEvaluationResult(
                    source_device=source_id, destination_device=destination_id,
                    is_reachable=False, protocol=protocol, destination_port=destination_port,
                    hop_count=0, path=[], hops_detail=[], total_latency_ms=0.0,
                    blocking_reason=f"Port {destination_port} is not listening on '{getattr(dst_dev, 'hostname', destination_id)}'."
                )

        # 1. Discover topological path
        path = cls.findPath(source_id, destination_id, respect_link_status=False)
        if not path:
            return ReachabilityEvaluationResult(
                source_device=source_id, destination_device=destination_id,
                is_reachable=False, protocol=protocol, destination_port=destination_port,
                hop_count=0, path=[], hops_detail=[], total_latency_ms=0.0,
                blocking_reason="No topological path exists in graph."
            )

        hops_detail: List[PathHopDetail] = []
        total_latency = 0.0

        for i, node_id in enumerate(path):
            node_dev = cls._resolve_device(node_id)
            node_zone = firewall_engine.getDeviceZone(node_id).value
            node_status = getattr(node_dev, "currentState", getattr(node_dev, "status", "ONLINE"))
            if hasattr(node_status, "value"):
                node_status = node_status.value

            if node_status not in ("ONLINE", "HEALTHY"):
                return ReachabilityEvaluationResult(
                    source_device=source_id, destination_device=destination_id,
                    is_reachable=False, protocol=protocol, destination_port=destination_port,
                    hop_count=len(path) - 1, path=path, hops_detail=hops_detail, total_latency_ms=total_latency,
                    blocking_reason=f"Intermediate hop '{getattr(node_dev, 'hostname', node_id)}' is {node_status}."
                )

            egress_conn_id = None
            if i < len(path) - 1:
                next_node_id = path[i + 1]
                conns = connection_registry.getAllConnections(device_id=node_id)
                active_conn = next(
                    (c for c in conns if (c.sourceDevice == node_id and c.destinationDevice == next_node_id) or
                                         (c.sourceDevice == next_node_id and c.destinationDevice == node_id)),
                    None
                )
                if active_conn:
                    if not cls._is_connection_active(active_conn):
                        c_status = active_conn.status.value if hasattr(active_conn.status, "value") else str(active_conn.status)
                        return ReachabilityEvaluationResult(
                            source_device=source_id, destination_device=destination_id,
                            is_reachable=False, protocol=protocol, destination_port=destination_port,
                            hop_count=len(path) - 1, path=path, hops_detail=hops_detail, total_latency_ms=total_latency,
                            blocking_reason=f"Connection '{active_conn.id}' is {c_status}."
                        )
                    egress_conn_id = active_conn.id
                    total_latency += active_conn.latency

            hops_detail.append(PathHopDetail(
                hop_number=i + 1,
                device_id=node_id,
                hostname=getattr(node_dev, "hostname", node_id),
                device_type=getattr(node_dev, "type", "NODE"),
                zone=node_zone,
                state=node_status,
                egress_connection_id=egress_conn_id,
                firewall_decision="PERMITTED"
            ))

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