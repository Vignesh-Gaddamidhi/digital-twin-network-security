import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.graph_models import (
    NodeTypeEnum, PathStatusEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.discovery.discovery_models import (
    PathConstraints, TraversalMethodEnum
)
from services.digital_twin.attack_path.discovery.path_discovery_engine import path_discovery_engine

def run_day137_suite():
    print("=" * 80)
    print("       WEEK 20 - DAY 137: PATH DISCOVERY & REACHABILITY AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    path_discovery_engine.clear()

    # 1. Single Path Discovery
    print("[1/12] Auditing Single Path Discovery (ATTACKER-EXT -> DB-01)...")
    res_single = path_discovery_engine.find_shortest_path("ATTACKER-EXT", "DB-01")
    print(f"    Paths Found : {res_single.pathsFound}")
    assert res_single.pathsFound >= 1
    p1 = res_single.paths[0]
    print(f"    Route : {' -> '.join(p1.nodeSequence)} [{p1.status.value}] ({p1.hopCount} hops)")
    assert p1.nodeSequence[0] == "ATTACKER-EXT"
    assert p1.nodeSequence[-1] == "DB-01"
    assert p1.status == PathStatusEnum.POSSIBLE
    print("    [PASS] Single valid path discovered.")

    # 2. Multiple Paths Discovery (Injecting APP-01 Pivot)
    print("\n[2/12] Auditing Multiple Alternate Paths Discovery (Adding APP-01)...")
    # Add APP-01
    attack_path_graph.add_node(AttackPathNode(
        nodeId="APP-01",
        deviceId="APP-01",
        nodeType=NodeTypeEnum.SERVER,
        hostname="app-01.dmz.internal",
        zone="DMZ",
        assetCriticality="HIGH",
        exposedPorts=[8080],
        reachable=True
    ))
    # CLIENT-01 -> APP-01
    attack_path_graph.add_edge(AttackPathEdge(
        edgeId="EDGE-CLIENT-APP",
        sourceNode="CLIENT-01",
        destinationNode="APP-01",
        destinationPort=8080,
        protocol="TCP",
        reachable=True
    ))
    # APP-01 -> DB-01
    attack_path_graph.add_edge(AttackPathEdge(
        edgeId="EDGE-APP-DB",
        sourceNode="APP-01",
        destinationNode="DB-01",
        destinationPort=3306,
        protocol="TCP",
        reachable=True
    ))

    res_multi = path_discovery_engine.find_all_paths("CLIENT-01", "DB-01")
    print(f"    Total Paths Discovered: {res_multi.pathsFound}")
    for p in res_multi.paths:
        print(f"      * {' -> '.join(p.nodeSequence)} [{p.status.value}]")

    assert res_multi.pathsFound >= 2
    chains = [tuple(p.nodeSequence) for p in res_multi.paths]
    assert ("CLIENT-01", "WEB-01", "DB-01") in chains
    assert ("CLIENT-01", "APP-01", "DB-01") in chains
    print("    [PASS] Multiple alternate attack paths discovered.")

    # 3. No Path Handling (Disconnected Subnet)
    print("\n[3/12] Auditing Disconnected Node (No Path Handling)...")
    attack_path_graph.add_node(AttackPathNode(
        nodeId="AIR-GAP-01",
        deviceId="AIR-GAP-01",
        hostname="isolated.internal",
        zone="MANAGEMENT",
        reachable=True
    ))
    res_none = path_discovery_engine.find_shortest_path("ATTACKER-EXT", "AIR-GAP-01")
    print(f"    Paths to Air-gapped Host: {res_none.pathsFound}")
    assert res_none.pathsFound == 0
    assert len(res_none.paths) == 0
    print("    [PASS] Zero paths reported for disconnected nodes.")

    # 4. Shortest Path (BFS) Minimum Hops
    print("\n[4/12] Auditing Shortest Path BFS Guarantee...")
    # 4a. Shortest path from ATTACKER-EXT to DB-01 (ATTACKER -> WEB -> DB = 2 hops)
    res_short_att = path_discovery_engine.find_shortest_path("ATTACKER-EXT", "DB-01")
    assert res_short_att.pathsFound == 1
    assert res_short_att.paths[0].hopCount == 2
    print(f"    ATTACKER-EXT -> DB-01 Shortest Hops : {res_short_att.paths[0].hopCount}")

    # 4b. Shortest REACHABLE path from CLIENT-01 to DB-01 (bypassing blocked direct edge)
    res_short_client = path_discovery_engine.find_shortest_path("CLIENT-01", "DB-01", only_reachable=True)
    assert res_short_client.pathsFound == 1
    assert res_short_client.paths[0].hopCount == 2
    assert res_short_client.paths[0].status == PathStatusEnum.POSSIBLE
    print(f"    CLIENT-01 -> DB-01 Shortest Reachable Hops : {res_short_client.paths[0].hopCount} ({' -> '.join(res_short_client.paths[0].nodeSequence)})")
    print("    [PASS] BFS shortest path verified.")

    # 5. Blocked Edge Detection (Direct CLIENT-01 -> DB-01 connection)
    print("\n[5/12] Auditing Blocked Path Due to Firewall Segmentation...")
    # Add direct connection from CLIENT-01 to DB-01 with BLOCKED status
    attack_path_graph.add_edge(AttackPathEdge(
        edgeId="EDGE-CLIENT-DB-BLOCKED",
        sourceNode="CLIENT-01",
        destinationNode="DB-01",
        destinationPort=3306,
        protocol="TCP",
        reachable=False,
        securityControl="FW-RULE-04: Internal to Database Direct Blocking",
        status="BLOCKED"
    ))

    # Evaluate direct reachability
    res_direct = path_discovery_engine.find_all_paths("CLIENT-01", "DB-01", PathConstraints(maxDepth=1))
    direct_path = next(p for p in res_direct.paths if len(p.nodeSequence) == 2)
    print(f"    Direct Route Status: {direct_path.status.value} (Reason: {direct_path.blockingReason})")
    assert direct_path.status == PathStatusEnum.BLOCKED
    assert "FW-RULE-04" in direct_path.blockingReason
    print("    [PASS] Blocked edge recorded accurately without deletion.")

    # 6. Partially Reachable Path Detection
    print("\n[6/12] Auditing Partially Reachable Path Classification...")
    # Sever WEB-01 -> DB-01
    edge_web_db = next(e for e in attack_path_graph.edges.values() if e.sourceNode == "WEB-01" and e.destinationNode == "DB-01")
    edge_web_db.reachable = False
    edge_web_db.status = "BLOCKED"
    edge_web_db.securityControl = "EMERGENCY-PORT-BLOCK"

    res_partial = path_discovery_engine.find_all_paths("ATTACKER-EXT", "DB-01")
    partial_path = next((p for p in res_partial.paths if p.status == PathStatusEnum.PARTIALLY_REACHABLE), None)
    assert partial_path is not None
    print(f"    Path: {' -> '.join(partial_path.nodeSequence)} | Status: {partial_path.status.value} | Blocked At: {partial_path.blockedAt}")
    assert partial_path.blockedAt == "DB-01"
    assert "EMERGENCY-PORT-BLOCK" in partial_path.blockingReason
    print("    [PASS] Partially reachable path correctly identified with blockage point.")

    # Restore edge
    edge_web_db.reachable = True
    edge_web_db.status = "REACHABLE"

    # 7. Isolated Node Handling
    print("\n[7/12] Auditing Path Pruning on Isolated Nodes...")
    web_node = attack_path_graph.get_node("WEB-01")
    web_node.securityState = "ISOLATED"
    res_iso = path_discovery_engine.find_all_paths("CLIENT-01", "DB-01")
    # All paths going through WEB-01 must be marked BLOCKED
    for p in res_iso.paths:
        if "WEB-01" in p.nodeSequence:
            print(f"    Isolated Traversal: {' -> '.join(p.nodeSequence)} -> Status: {p.status.value}")
            assert p.status == PathStatusEnum.BLOCKED
    print("    [PASS] Isolated nodes prune viable traversals.")
    web_node.securityState = "NORMAL"

    # 8. Maximum Depth Constraint
    print("\n[8/12] Auditing Maximum Depth Bound Constraint...")
    res_depth = path_discovery_engine.find_all_paths("ATTACKER-EXT", "DB-01", PathConstraints(maxDepth=2))
    for p in res_depth.paths:
        print(f"    Depth-Bounded Path: {p.hopCount} hops (Max: 2)")
        assert p.hopCount <= 2
    print("    [PASS] Depth constraint enforced.")

    # 9. Maximum Path Count Constraint
    print("\n[9/12] Auditing Max Paths Result Count Cap...")
    res_cap = path_discovery_engine.find_all_paths("CLIENT-01", "DB-01", PathConstraints(maxPaths=1))
    print(f"    Paths Returned under MaxPaths=1: {res_cap.pathsFound}")
    assert res_cap.pathsFound == 1
    print("    [PASS] Max paths cap enforced.")

    # 10. Cyclic Graph Traversal & Loop Prevention
    print("\n[10/12] Auditing Cycle Prevention on Loops (A -> B -> A)...")
    # Add cycle edge: WEB-01 -> CLIENT-01
    attack_path_graph.add_edge(AttackPathEdge(
        edgeId="EDGE-CYCLE-WEB-CLIENT",
        sourceNode="WEB-01",
        destinationNode="CLIENT-01",
        protocol="TCP",
        destinationPort=445,
        reachable=True
    ))
    res_cycle = path_discovery_engine.find_all_paths("CLIENT-01", "DB-01")
    print(f"    Paths Discovered with Cycle Present: {res_cycle.pathsFound}")
    for p in res_cycle.paths:
        # Assert no node appears more than once in the sequence
        assert len(p.nodeSequence) == len(set(p.nodeSequence)), f"Cycle detected in sequence: {p.nodeSequence}"
    print("    [PASS] Traversal terminated safely with zero infinite loops.")

    # 11. Duplicate Path Suppression
    print("\n[11/12] Auditing Duplicate Path Suppression...")
    chains_set = set(tuple(p.nodeSequence) for p in res_cycle.paths)
    assert len(chains_set) == len(res_cycle.paths)
    print("    [PASS] All returned paths are distinct.")

    # 12. Path Direction Preservation
    print("\n[12/12] Auditing Path Direction Invariant...")
    res_rev = path_discovery_engine.find_shortest_path("DB-01", "ATTACKER-EXT")
    print(f"    Reverse Traversal from DB-01 to ATTACKER-EXT: {res_rev.pathsFound} paths")
    assert res_rev.pathsFound == 0
    print("    [PASS] Direction strictly enforced: Database cannot reach Attacker.")

    # Verify Summary String & Disk Persistence
    print("\n" + res_single.to_formatted_summary())
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path" / "path_discoveries.json"
    assert out_file.exists()
    print("    [PASS] Discovery records persisted and verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 137 PATH DISCOVERY & REACHABILITY TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    run_day137_suite()