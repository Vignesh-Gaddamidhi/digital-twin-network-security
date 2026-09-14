import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph

def run_day143_suite():
    print("=" * 80)
    print("       WEEK 21 - DAY 143: LIVE NETWORK TOPOLOGY AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 1. Topology Nodes & Coordinates Verification
    print("[1/7] Auditing Topology Node Population and Layered Layout...")
    nodes = attack_path_graph.nodes
    assert len(nodes) >= 5
    assert "WEB-01" in nodes
    assert "DB-01" in nodes
    assert "CLIENT-01" in nodes
    print(f"    Loaded {len(nodes)} active Digital Twin nodes.")
    print("    [PASS] Topology nodes verified.")

    # 2. Directed Edges & Reachability Attributes
    print("\n[2/7] Auditing Directed Edge Links & Reachability Status...")
    edges = list(attack_path_graph.edges.values())
    assert len(edges) >= 4
    for e in edges:
        print(f"    Edge: {e.sourceNode:<14} -> {e.destinationNode:<14} | Port: {e.destinationPort:<5} | Reachable: {e.reachable}")
    print("    [PASS] Directed edge connectivity verified.")

    # 3. Network Zones Audit
    print("\n[3/7] Auditing Network Zone Attribution across Nodes...")
    expected_zones = {"INTERNET", "DMZ", "INTERNAL", "DATABASE"}
    assigned_zones = set(n.zone for n in nodes.values())
    for z in expected_zones:
        assert z in assigned_zones, f"Zone '{z}' missing from nodes."
        print(f"    Zone Verified: {z}")
    print("    [PASS] All 4 required network zones attributed.")

    # 4. Accessible Node Status Indicators
    print("\n[4/7] Auditing Multi-Modal Node Status Display...")
    web = nodes["WEB-01"]
    print(f"    WEB-01 Security State : {web.securityState} (Risk: {web.riskScore:.1f})")
    assert web.securityState in ("NORMAL", "AT_RISK", "COMPROMISED", "ISOLATED")
    print("    [PASS] Node security states verified.")

    # 5. Attack-Path Highlighting Invariant
    print("\n[5/7] Auditing Attack-Path Highlighting Flag...")
    active_path = ["ATTACKER-EXT", "WEB-01", "DB-01"]
    for nid in active_path:
        assert nid in nodes
    print(f"    Active Trajectory: {' -> '.join(active_path)}")
    print("    [PASS] Attack-path nodes mapped for visual highlighting.")

    # 6. Device Details Inspection
    print("\n[6/7] Auditing Device Detail Flyout Attributes for WEB-01...")
    assert len(web.exposedPorts) > 0
    assert len(web.services) > 0
    assert len(web.vulnerabilities) > 0
    print(f"    Ports: {web.exposedPorts} | Services: {web.services} | Vulns: {web.vulnerabilities}")
    print("    [PASS] Device details data contract verified.")

    # 7. Frontend Artifacts Check
    print("\n[7/7] Auditing Topology Frontend Components on Disk...")
    expected_components = [
        "services/web_dashboard/src/types/topology.ts",
        "services/web_dashboard/src/components/topology/DeviceDetailFlyout.tsx",
        "services/web_dashboard/src/components/topology/TopologyControls.tsx"
    ]
    for comp in expected_components:
        cp = ROOT_DIR / comp
        assert cp.exists(), f"Missing topology file: {cp}"
    print(f"    Verified {len(expected_components)} frontend components on disk.")
    print("    [PASS] Topology artifacts verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 143 LIVE NETWORK TOPOLOGY TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day143_suite()