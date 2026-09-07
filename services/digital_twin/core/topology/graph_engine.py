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

    def addNode(self, node: GraphNodeModel) -> GraphNodeModel:
        if node.id in self._nodes:
            raise NodeAlreadyExistsError(f"Node with ID '{node.id}' already exists in graph.")

        self._nodes[node.id] = node
        self._graph.add_node(
            node.id,
            type=node.type,
            label=node.label,
            zone=node.zone,
            state=node.state,
            **node.metadata
        )
        return node

    def removeNode(self, node_id: str) -> bool:
        if node_id not in self._nodes:
            raise NodeNotFoundError(f"Cannot remove: Node '{node_id}' not found in graph.")

        # Identify all associated edges to clean internal index
        edges_to_remove = [
            e_id for e_id, edge in self._edges.items()
            if edge.source == node_id or edge.target == node_id
        ]
        for e_id in edges_to_remove:
            del self._edges[e_id]

        self._graph.remove_node(node_id)
        del self._nodes[node_id]
        return True

    def addEdge(self, edge: GraphEdgeModel, is_bidirectional: bool = False) -> GraphEdgeModel:
        if edge.id in self._edges:
            raise EdgeAlreadyExistsError(f"Edge with ID '{edge.id}' already exists in graph.")

        if edge.source not in self._nodes:
            raise NodeNotFoundError(f"Source node '{edge.source}' not registered in graph.")

        if edge.target not in self._nodes:
            raise NodeNotFoundError(f"Target node '{edge.target}' not registered in graph.")

        self._edges[edge.id] = edge
        self._graph.add_edge(
            edge.source,
            edge.target,
            key=edge.id,
            protocol=edge.protocol,
            status=edge.status,
            weight=edge.weight,
            **edge.metadata
        )

        if is_bidirectional:
            rev_id = f"{edge.id}-rev"
            self._graph.add_edge(
                edge.target,
                edge.source,
                key=rev_id,
                protocol=edge.protocol,
                status=edge.status,
                weight=edge.weight,
                **edge.metadata
            )

        return edge

    def removeEdge(self, edge_id: str) -> bool:
        if edge_id not in self._edges:
            raise EdgeNotFoundError(f"Cannot remove: Edge '{edge_id}' not found in graph.")

        edge = self._edges[edge_id]

        # Remove from NetworkX
        if self._graph.has_edge(edge.source, edge.target, key=edge_id):
            self._graph.remove_edge(edge.source, edge.target, key=edge_id)

        # Remove reverse edge if present
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