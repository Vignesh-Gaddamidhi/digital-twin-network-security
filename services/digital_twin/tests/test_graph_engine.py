import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.graph import GraphNodeModel, GraphEdgeModel
from services.digital_twin.core.topology.graph_engine import (
    graph_engine, NodeAlreadyExistsError, NodeNotFoundError, EdgeAlreadyExistsError
)

def run_graph_engine_suite():
    print("================================================================================")
    print("       WEEK 6 - DAY 36: GRAPH ENGINE G = (V, E) VALIDATION AUDIT                ")
    print("================================================================================\n")

    graph_engine.clear()

    # 1. Populate Vertices (V)
    print("[1/5] Populating Graph Nodes V = {Firewall, Router, Web, DB, DNS, PC1, PC2}...")
    nodes = [
        GraphNodeModel(id="firewall-01", type="FIREWALL", label="Perimeter Firewall", zone="EXTERNAL", state="ACTIVE"),
        GraphNodeModel(id="router-01", type="ROUTER", label="Core Gateway Router", zone="INTERNAL", state="ACTIVE"),
        GraphNodeModel(id="web-server-01", type="SERVER", label="Web Server", zone="DMZ", state="ACTIVE"),
        GraphNodeModel(id="db-server-01", type="SERVER", label="Database Server", zone="DATABASE", state="ACTIVE"),
        GraphNodeModel(id="dns-server-01", type="SERVER", label="DNS Server", zone="INTERNAL", state="ACTIVE"),
        GraphNodeModel(id="pc-01", type="CLIENT", label="Workstation 1", zone="INTERNAL", state="ACTIVE"),
        GraphNodeModel(id="pc-02", type="CLIENT", label="Workstation 2", zone="INTERNAL", state="ACTIVE"),
    ]

    for n in nodes:
        graph_engine.addNode(n)
        print(f"    [+] Added Node: {n.id:15s} | Label: {n.label:20s} | Zone: {n.zone}")

    assert len(graph_engine.getNodes()) == 7
    print("    [PASS] Successfully registered 7 canonical nodes in V.")

    # 2. Populate Edges (E)
    print("\n[2/5] Connecting Directed Edges E...")
    edges = [
        GraphEdgeModel(id="conn-fw-rtr", source="firewall-01", target="router-01", protocol="IP", status="ACTIVE"),
        GraphEdgeModel(id="conn-rtr-web", source="router-01", target="web-server-01", protocol="TCP", status="ACTIVE"),
        GraphEdgeModel(id="conn-rtr-db", source="router-01", target="db-server-01", protocol="TCP", status="ACTIVE"),
        GraphEdgeModel(id="conn-rtr-dns", source="router-01", target="dns-server-01", protocol="UDP", status="ACTIVE"),
        GraphEdgeModel(id="conn-web-pc1", source="web-server-01", target="pc-01", protocol="TCP", status="ACTIVE"),
    ]

    for e in edges:
        graph_engine.addEdge(e)
        print(f"    [+] Added Edge: {e.id:15s} | {e.source:15s} -> {e.target:15s} ({e.protocol})")

    assert len(graph_engine.getEdges()) == 5
    print("    [PASS] Successfully established 5 directed edges in E.")

    # 3. Test Inbound & Outbound Neighbor Adjacency
    print("\n[3/5] Testing Adjacency for Router (router-01)...")
    rtr_neighbors = graph_engine.getNeighbors("router-01")
    print(f"    Inbound Predecessors : {rtr_neighbors.inbound_neighbors} (In-Degree: {rtr_neighbors.in_degree})")
    print(f"    Outbound Successors  : {rtr_neighbors.outbound_neighbors} (Out-Degree: {rtr_neighbors.out_degree})")
    print(f"    Total Neighbors      : {rtr_neighbors.all_neighbors}")

    assert rtr_neighbors.inbound_neighbors == ["firewall-01"]
    assert sorted(rtr_neighbors.outbound_neighbors) == ["db-server-01", "dns-server-01", "web-server-01"]
    assert rtr_neighbors.in_degree == 1
    assert rtr_neighbors.out_degree == 3
    print("    [PASS] Adjacency matches expected topological tree.")

    # 4. Error Handling & Relational Integrity
    print("\n[4/5] Testing Boundary Rejections (Duplicate Nodes & Unknown Endpoints)...")
    try:
        graph_engine.addNode(nodes[0])
        assert False, "Failed to reject duplicate node!"
    except NodeAlreadyExistsError as e:
        print(f"    [PASS] Safely rejected duplicate node: {e}")

    try:
        graph_engine.addEdge(GraphEdgeModel(id="conn-ghost", source="ghost-device", target="pc-01"))
        assert False, "Failed to reject unknown source device!"
    except NodeNotFoundError as e:
        print(f"    [PASS] Safely rejected edge with unknown source: {e}")

    # 5. Cascading Node Deletion
    print("\n[5/5] Testing Cascading Deletion of Node (web-server-01)...")
    # web-server-01 has 1 inbound edge (router-01) and 1 outbound edge (pc-01)
    graph_engine.removeNode("web-server-01")
    assert len(graph_engine.getNodes()) == 6
    remaining_edge_ids = [e.id for e in graph_engine.getEdges()]
    assert "conn-rtr-web" not in remaining_edge_ids
    assert "conn-web-pc1" not in remaining_edge_ids
    print(f"    [PASS] Node removed and incident edges cascaded. Remaining edges count: {len(remaining_edge_ids)}")

    # 6. Snapshot Export
    snapshot = graph_engine.getSnapshot()
    assert snapshot.node_count == 6
    assert snapshot.edge_count == 3
    print(f"\n[*] Exported Graph Snapshot: {snapshot.node_count} nodes, {snapshot.edge_count} edges.")

    print("\n================================================================================")
    print("       ALL GRAPH ENGINE TESTS PASSED CLEANLY                                    ")
    print("================================================================================")

if __name__ == "__main__":
    run_graph_engine_suite()