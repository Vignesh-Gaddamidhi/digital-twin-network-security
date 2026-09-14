import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.graph_models import (
    NodeTypeEnum, PathStatusEnum, AttackPathNode, AttackPathEdge, AttackPath
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph

def run_day134_suite():
    print("=" * 80)
    print("       WEEK 20 - DAY 134: ATTACK PATH GRAPH FUNDAMENTALS AUDIT")
    print("=" * 80 + "\n")

    # 1. Graph Loads
    print("[1/10] Auditing Attack Path Graph Initialization...")
    attack_path_graph._initialize_default_topology()
    assert attack_path_graph is not None
    print(f"    Nodes Count : {len(attack_path_graph.nodes)}")
    print(f"    Edges Count : {len(attack_path_graph.edges)}")
    assert len(attack_path_graph.nodes) >= 5
    assert len(attack_path_graph.edges) >= 4
    print("    [PASS] Graph loaded with default topology.")

    # 2. Nodes Load & Verify Attributes
    print("\n[2/10] Auditing Node Population and Security Context...")
    client = attack_path_graph.get_node("CLIENT-01")
    web = attack_path_graph.get_node("WEB-01")
    db = attack_path_graph.get_node("DB-01")

    print(f"    CLIENT-01 : Zone={client.zone:<10} | Crit={client.assetCriticality:<8} | Ports={client.exposedPorts}")
    print(f"    WEB-01    : Zone={web.zone:<10} | Crit={web.assetCriticality:<8} | Vulns={web.vulnerabilities}")
    print(f"    DB-01     : Zone={db.zone:<10} | Crit={db.assetCriticality:<8} | Vulns={db.vulnerabilities}")

    assert client.zone == "USER_LAN"
    assert web.assetCriticality == "HIGH"
    assert db.assetCriticality == "CRITICAL"
    print("    [PASS] Nodes loaded with complete security context.")

    # 3. Edges Load
    print("\n[3/10] Auditing Edge Connections...")
    out_client = attack_path_graph.get_outgoing_edges("CLIENT-01")
    print(f"    CLIENT-01 Outgoing Edges: {[e.destinationNode for e in out_client]}")
    destinations = [e.destinationNode for e in out_client]
    assert "WEB-01" in destinations
    assert "DNS-SERVER-01" in destinations
    print("    [PASS] Directed outgoing edges loaded.")

    # 4. Direction is Preserved (Asymmetry Invariant)
    print("\n[4/10] Auditing Directed Edge Asymmetry (CLIENT-01 -> WEB-01 vs WEB-01 -> CLIENT-01)...")
    has_fwd = attack_path_graph.has_directed_edge("CLIENT-01", "WEB-01")
    has_rev = attack_path_graph.has_directed_edge("WEB-01", "CLIENT-01")

    print(f"    CLIENT-01 -> WEB-01 : {has_fwd} (Expected: True)")
    print(f"    WEB-01 -> CLIENT-01 : {has_rev} (Expected: False)")

    assert has_fwd is True
    assert has_rev is False
    print("    [PASS] Graph direction strictly preserved.")

    # 5. Duplicate Nodes Rejected
    print("\n[5/10] Auditing Duplicate Node Rejection...")
    dup_caught = False
    try:
        attack_path_graph.add_node(AttackPathNode(
            nodeId="CLIENT-01",
            deviceId="CLIENT-01",
            hostname="client-dup.internal"
        ))
    except ValueError as e:
        dup_caught = "DUPLICATE_NODE" in str(e)
    assert dup_caught
    print("    [PASS] Duplicate node ID rejected with ValueError.")

    # 6. Invalid Edges Rejected
    print("\n[6/10] Auditing Invalid Edge Rejection (Non-Existent Endpoints)...")
    edge_err_caught = False
    try:
        attack_path_graph.add_edge(AttackPathEdge(
            edgeId="EDGE-FAIL",
            sourceNode="CLIENT-01",
            destinationNode="GHOST-ROUTER-99"
        ))
    except KeyError as e:
        edge_err_caught = "INVALID_EDGE" in str(e)
    assert edge_err_caught
    print("    [PASS] Edge referencing non-existent node rejected with KeyError.")

    # 7. Unknown Devices Handled
    print("\n[7/10] Auditing Unknown Device Retrieval Error Handling...")
    unknown_caught = False
    try:
        attack_path_graph.get_node("NON-EXISTENT-DEV")
    except KeyError as e:
        unknown_caught = "UNKNOWN_DEVICE" in str(e)
    assert unknown_caught
    print("    [PASS] Unknown device raises KeyError cleanly.")

    # 8. Attacker Node Creation & Validation
    print("\n[8/10] Auditing Attacker Node Ingress...")
    attacker = attack_path_graph.get_node("ATTACKER-EXT")
    assert attacker.nodeType == NodeTypeEnum.ATTACKER
    assert attacker.zone == "INTERNET"
    print(f"    Attacker Node Verified: {attacker.nodeId} ({attacker.hostname})")
    print("    [PASS] Attacker node validated.")

    # 9. Target Node Creation & Validation
    print("\n[9/10] Auditing Target Database Node...")
    target = attack_path_graph.get_node("DB-01")
    assert target.nodeType == NodeTypeEnum.DATABASE
    assert target.assetCriticality == "CRITICAL"
    print(f"    Target Node Verified: {target.nodeId} (Crit: {target.assetCriticality})")
    print("    [PASS] Target node validated.")

    # 10. AttackPath Schema Validation & Path Construction
    print("\n[10/10] Auditing Multi-Hop AttackPath Construction...")
    chain = ["ATTACKER-EXT", "CLIENT-01", "WEB-01", "DB-01"]
    path_obj = attack_path_graph.build_path(
        attacker="ATTACKER-EXT",
        entry_node="CLIENT-01",
        target_node="DB-01",
        node_chain=chain,
        status=PathStatusEnum.POSSIBLE,
        risk_score=69.6,
        risk_level="HIGH"
    )

    print(f"\n{path_obj.to_summary_string()}")
    assert path_obj.pathLength == 3
    assert path_obj.entryNode == "CLIENT-01"
    assert path_obj.targetNode == "DB-01"
    assert path_obj.pathStatus == PathStatusEnum.POSSIBLE
    assert len(path_obj.edges) == 3
    assert "CVE-2026-SQLI" in path_obj.vulnerabilities

    # Verify Graph Snapshot on Disk
    snapshot = attack_path_graph.snapshot()
    assert snapshot["nodeCount"] >= 5
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path" / "graph_snapshot.json"
    assert out_file.exists()
    print("    [PASS] AttackPath container and graph snapshot verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 134 ATTACK PATH GRAPH TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day134_suite()