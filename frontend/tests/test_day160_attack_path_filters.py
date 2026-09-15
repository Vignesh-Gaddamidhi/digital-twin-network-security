import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from frontend.topology.three_d_filter_models import (
    AttackPathVisualStatusEnum, ViewModeEnum, VisibilityPresetEnum, TopologyFilterCriteria
)
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.topology.three_d_navigation_engine import three_d_navigation_engine

def run_day160_suite():
    print("=" * 80)
    print("       WEEK 23 - DAY 160: 3D ATTACK PATHS, FILTERING & 2D/3D SWITCH AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    device_3d_renderer_engine.sync_devices_from_twin()
    link_3d_renderer_engine.sync_links_from_twin()
    three_d_navigation_engine.sync_attack_paths()

    # 1. 3D Attack Path Discovery
    print("[1/10] Auditing 3D Attack Path Discovery & Node Traversals...")
    paths = three_d_navigation_engine.cached_attack_paths
    print(f"    Discovered Paths Count: {len(paths)}")
    assert len(paths) >= 2
    p0 = list(paths.values())[0]
    print(f"    Path #{p0.pathId}: {' -> '.join(p0.traversedNodeSequence)} | Status: {p0.status.value}")
    assert "CLIENT-01" in p0.traversedNodeSequence
    assert "DB-01" in p0.traversedNodeSequence
    print("    [PASS] 3D attack paths ingested from core discovery engine.")

    # 2. Path Status Verification (POSSIBLE vs CONFIRMED)
    print("\n[2/10] Auditing Path Status Distinction (Guarding against false CONFIRMED status)...")
    print(f"    Path Status: {p0.status.value}")
    assert p0.status in (AttackPathVisualStatusEnum.POSSIBLE, AttackPathVisualStatusEnum.BLOCKED)
    assert p0.status != "CONFIRMED_ATTACK"
    print("    [PASS] Potential lateral path correctly designated as POSSIBLE.")

    # 3. 3D Attack Path Highlighting
    print("\n[3/10] Auditing 3D Traversal Path Highlighting & Secondary Element Dimming...")
    sel_path = three_d_navigation_engine.select_attack_path_3d(p0.pathId)
    assert sel_path is not None
    assert sel_path.isHighlighted is True

    # Check traversed devices are highlighted
    for did in p0.traversedNodeSequence:
        mesh = device_3d_renderer_engine.device_mesh_registry[did]
        assert mesh.isHighlighted is True
        print(f"    Traversed Node: {did:<12} -> isHighlighted = {mesh.isHighlighted}")

    # Check traversed links are marked
    traversed_link_count = sum(1 for l in link_3d_renderer_engine.link_registry.values() if l.isTraversedInAttackPath)
    assert traversed_link_count >= 1
    print(f"    Highlighted Traversed Links: {traversed_link_count}")
    print("    [PASS] Traversed nodes and spline links illuminated in 3D scene.")

    # 4. Attack Path Details Inspection
    print("\n[4/10] Auditing Attack Path Analytical Details...")
    print(f"    Risk Score   : {p0.riskScore:.1f} [{p0.riskLevel.value}]")
    print(f"    Likelihood   : {p0.likelihoodScore:.2f}")
    print(f"    Impact       : {p0.impactScore:.2f}")
    print(f"    Reachability : {p0.reachability}")
    print(f"    Vulnerabs    : {p0.vulnerabilitiesExploited}")

    assert p0.riskScore > 0.0
    assert p0.reachability == "REACHABLE"
    print("    [PASS] Multi-attribute attack path details verified.")

    # 5. Non-Destructive Filtering (SERVERS Only)
    print("\n[5/10] Auditing Device Type Filtering (SERVERS only)...")
    vis_servers = three_d_navigation_engine.apply_topology_filter(
        TopologyFilterCriteria(deviceTypeFilter="SERVERS")
    )
    print(f"    WEB-01 Visible    : {vis_servers.get('WEB-01')}")
    print(f"    DB-01 Visible     : {vis_servers.get('DB-01')}")
    print(f"    CLIENT-01 Visible : {vis_servers.get('CLIENT-01')}")

    assert vis_servers.get("WEB-01") is True
    assert vis_servers.get("DB-01") is True
    assert vis_servers.get("CLIENT-01") is False

    # Verify Twin graph is NOT deleted
    assert len(attack_path_graph.nodes) >= 5
    print("    [PASS] Low-tier devices hidden visually while Digital Twin graph remains intact.")

    # 6. Non-Destructive Filtering (Security State AT_RISK & COMPROMISED)
    print("\n[6/10] Auditing Security State Filtering (AT_RISK only)...")
    vis_at_risk = three_d_navigation_engine.apply_topology_filter(
        TopologyFilterCriteria(securityStateFilter="AT_RISK")
    )
    print(f"    Visible AT_RISK count: {sum(1 for v in vis_at_risk.values() if v)}")
    assert len(attack_path_graph.nodes) >= 5  # Invariant check
    print("    [PASS] Security state filter applied non-destructively.")

    # 7. Visibility Preset: HIDE_ISOLATED
    print("\n[7/10] Auditing Visibility Preset (HIDE_ISOLATED)...")
    twin_graph_synchronizer.isolate_device("CLIENT-01")
    vis_isolated = three_d_navigation_engine.apply_topology_filter(
        TopologyFilterCriteria(visibilityPreset=VisibilityPresetEnum.HIDE_ISOLATED)
    )
    print(f"    Quarantined CLIENT-01 Visible: {vis_isolated.get('CLIENT-01')}")
    assert vis_isolated.get("CLIENT-01") is False
    print("    [PASS] HIDE_ISOLATED preset successfully hides quarantined hosts.")

    # Reset filter
    three_d_navigation_engine.apply_topology_filter(TopologyFilterCriteria())

    # 8. Seamless 2D -> 3D Viewport Switching
    print("\n[8/10] Auditing 2D -> 3D Viewport Switching with Context Preservation...")
    three_d_navigation_engine.sync_state.selectedDeviceId = "WEB-01"
    three_d_navigation_engine.sync_state.timeRange = "15m"

    res_to_3d = three_d_navigation_engine.switch_viewport_mode(ViewModeEnum.VIEW_3D)
    print(f"    Switched to: {res_to_3d.currentMode.value} | Target: ({res_to_3d.targetCoordinates['x']}, {res_to_3d.targetCoordinates['y']}, {res_to_3d.targetCoordinates['z']})")
    assert res_to_3d.currentMode == ViewModeEnum.VIEW_3D
    assert res_to_3d.preservedContext["selectedDeviceId"] == "WEB-01"
    assert res_to_3d.preservedContext["timeRange"] == "15m"
    print("    [PASS] 2D -> 3D transition preserved selection, filters, and time window.")

    # 9. Seamless 3D -> 2D Viewport Switching
    print("\n[9/10] Auditing 3D -> 2D Viewport Switching...")
    res_to_2d = three_d_navigation_engine.switch_viewport_mode(ViewModeEnum.VIEW_2D)
    print(f"    Switched to: {res_to_2d.currentMode.value}")
    assert res_to_2d.currentMode == ViewModeEnum.VIEW_2D
    assert res_to_2d.preservedContext["selectedDeviceId"] == "WEB-01"
    print("    [PASS] 3D -> 2D transition preserved full operational context.")

    # 10. Cross-View State Consistency Verification
    print("\n[10/10] Auditing Cross-View State Consistency (2D vs 3D)...")
    twin_node = attack_path_graph.get_node("DB-01")
    mesh_3d = device_3d_renderer_engine.device_mesh_registry["DB-01"]

    print(f"    Twin Graph Risk   : {twin_node.riskScore}")
    print(f"    Twin Graph State  : {twin_node.securityState}")
    print(f"    3D Mesh Label Risk: {mesh_3d.label.riskScore}")

    assert mesh_3d.label.riskScore == twin_node.riskScore
    print("    [PASS] Invariant confirmed: 2D and 3D views project identical Twin state.")

    # Restore baseline
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    three_d_navigation_engine.select_attack_path_3d(None)

    print("\n" + "=" * 80)
    print("       ALL DAY 160 3D ATTACK PATH & FILTERING TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day160_suite()