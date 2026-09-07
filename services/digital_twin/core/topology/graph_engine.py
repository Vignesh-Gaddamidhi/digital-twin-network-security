from typing import Dict, List, Optional, Any
import networkx as nx

from packages.shared_types.src.graph import (
    GraphNodeModel, GraphEdgeModel, GraphNeighborsResult, GraphSnapshotModel
)

class NodeAlreadyExistsError(ValueError):
    pass

class NodeNotFoundError(KeyError):
    pass

class EdgeAlreadyExistsError(ValueError):
    pass

class EdgeNotFoundError(KeyError):
    pass

class GraphEngine:
    """Mathematical graph representation G = (V, E) of the Network Digital Twin."""

    def __init__(self):
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._nodes: Dict[str, GraphNodeModel] = {}
        self._edges: Dict[str, GraphEdgeModel] = {}

    def addNode(self, node: Any) -> GraphNodeModel:
        # Support both GraphNodeModel, NetworkDeviceModel, or raw dicts
        if isinstance(node, dict):
            node_id = node.get("id")
            node_type = node.get("type", "SERVER")
            if hasattr(node_type, "value"):
                node_type = node_type.value
            label = node.get("label", node.get("hostname", node_id))
            zone = node.get("zone", node.get("networkZone", "INTERNAL"))
            if hasattr(zone, "value"):
                zone = zone.value
            state = node.get("state", node.get("currentState", "ACTIVE"))
            metadata = node.get("metadata", {})
            node_model = GraphNodeModel(id=node_id, type=str(node_type), label=str(label), zone=str(zone), state=str(state), metadata=metadata)
        elif hasattr(node, "id"):
            node_id = node.id
            node_type = getattr(node, "type", "SERVER")
            if hasattr(node_type, "value"):
                node_type = node_type.value
            label = getattr(node, "label", getattr(node, "hostname", node_id))
            zone = getattr(node, "zone", getattr(node, "networkZone", "INTERNAL"))
            if hasattr(zone, "value"):
                zone = zone.value
            state = getattr(node, "state", getattr(node, "currentState", "ACTIVE"))
            metadata = getattr(node, "metadata", {})
            node_model = GraphNodeModel(id=node_id, type=str(node_type), label=str(label), zone=str(zone), state=str(state), metadata=metadata)
        else:
            raise TypeError("Invalid node object passed to addNode.")

        if node_model.id in self._nodes:
            # Update existing instead of hard crashing if re-registered
            self._nodes[node_model.id] = node_model
            self._graph.nodes[node_model.id].update(node_model.model_dump())
            return node_model

        self._nodes[node_model.id] = node_model
        self._graph.add_node(
            node_model.id,
            type=node_model.type,
            label=node_model.label,
            zone=node_model.zone,
            state=node_model.state,
            **node_model.metadata
        )
        return node_model

    def removeNode(self, node_id: str) -> bool:
        if node_id not in self._nodes:
            raise NodeNotFoundError(f"Cannot remove: Node '{node_id}' not found in graph.")

        edges_to_remove = [
            e_id for e_id, edge in self._edges.items()
            if edge.source == node_id or edge.target == node_id
        ]
        for e_id in edges_to_remove:
            del self._edges[e_id]

        self._graph.remove_node(node_id)
        del self._nodes[node_id]
        return True

    def addEdge(self, edge: Any, is_bidirectional: bool = False) -> GraphEdgeModel:
        if isinstance(edge, dict):
            edge_model = GraphEdgeModel(**edge)
        elif hasattr(edge, "id"):
            edge_id = edge.id
            src = getattr(edge, "source", getattr(edge, "sourceDevice", None))
            tgt = getattr(edge, "target", getattr(edge, "destinationDevice", None))
            proto = getattr(edge, "protocol", "TCP")
            if hasattr(proto, "value"):
                proto = proto.value
            status = getattr(edge, "status", "ACTIVE")
            if hasattr(status, "value"):
                status = status.value
            weight = getattr(edge, "weight", getattr(edge, "latency", 1.0))
            metadata = getattr(edge, "metadata", {})
            edge_model = GraphEdgeModel(id=edge_id, source=src, target=tgt, protocol=str(proto), status=str(status), weight=float(weight), metadata=metadata)
        else:
            raise TypeError("Invalid edge object passed to addEdge.")

        if edge_model.id in self._edges:
            self._edges[edge_model.id] = edge_model
            return edge_model

        if edge_model.source not in self._nodes:
            raise NodeNotFoundError(f"Source node '{edge_model.source}' not registered in graph.")

        if edge_model.target not in self._nodes:
            raise NodeNotFoundError(f"Target node '{edge_model.target}' not registered in graph.")

        self._edges[edge_model.id] = edge_model
        self._graph.add_edge(
            edge_model.source,
            edge_model.target,
            key=edge_model.id,
            protocol=edge_model.protocol,
            status=edge_model.status,
            weight=edge_model.weight,
            **edge_model.metadata
        )

        if is_bidirectional:
            rev_id = f"{edge_model.id}-rev"
            self._graph.add_edge(
                edge_model.target,
                edge_model.source,
                key=rev_id,
                protocol=edge_model.protocol,
                status=edge_model.status,
                weight=edge_model.weight,
                **edge_model.metadata
            )

        return edge_model

    def removeEdge(self, edge_id: str) -> bool:
        if edge_id not in self._edges:
            raise EdgeNotFoundError(f"Cannot remove: Edge '{edge_id}' not found.")

        edge = self._edges[edge_id]

        if self._graph.has_edge(edge.source, edge.target, key=edge_id):
            self._graph.remove_edge(edge.source, edge.target, key=edge_id)

        rev_id = f"{edge_id}-rev"
        if self._graph.has_edge(edge.target, edge.source, key=rev_id):
            self._graph.remove_edge(edge.target, edge.source, key=rev_id)

        del self._edges[edge_id]
        return True

    def getNeighbors(self, node_id: str) -> GraphNeighborsResult:
        if node_id not in self._nodes:
            raise NodeNotFoundError(f"Node '{node_id}' does not exist in graph.")

        outbound = list(self._graph.successors(node_id))
        inbound = list(self._graph.predecessors(node_id))
        all_unique = sorted(list(set(outbound + inbound)))

        return GraphNeighborsResult(
            node_id=node_id,
            inbound_neighbors=inbound,
            outbound_neighbors=outbound,
            all_neighbors=all_unique,
            in_degree=len(inbound),
            out_degree=len(outbound)
        )

    def getNodes(self, zone: Optional[str] = None, node_type: Optional[str] = None) -> List[GraphNodeModel]:
        nodes = list(self._nodes.values())
        if zone:
            nodes = [n for n in nodes if n.zone.upper() == zone.upper()]
        if node_type:
            nodes = [n for n in nodes if n.type.upper() == node_type.upper()]
        return nodes

    def getEdges(self, status: Optional[str] = None, protocol: Optional[str] = None) -> List[GraphEdgeModel]:
        edges = list(self._edges.values())
        if status:
            edges = [e for e in edges if e.status.upper() == status.upper()]
        if protocol:
            edges = [e for e in edges if e.protocol.upper() == protocol.upper()]
        return edges

    def getSnapshot(self) -> GraphSnapshotModel:
        return GraphSnapshotModel(
            node_count=len(self._nodes),
            edge_count=len(self._edges),
            nodes=list(self._nodes.values()),
            edges=list(self._edges.values())
        )

    def clear(self):
        self._graph.clear()
        self._nodes.clear()
        self._edges.clear()

graph_engine = GraphEngine()