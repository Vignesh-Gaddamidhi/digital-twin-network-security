import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.three_d_twin_contract import MeshArchetypeEnum, DeviceTo3DMapper
from frontend.topology.three_d_projection_engine import three_d_projection_engine

def run_day155_suite():
    print("=" * 80)
    print("       WEEK 23 - DAY 155: 3D DIGITAL TWIN ARCHITECTURE & CONTRACT AUDIT")
    print("=" * 80 + "\n")

    # Baseline seed
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 1. 3D Twin State Extraction
    print("[1/7] Auditing 3D Twin State Construction from Backend Graph...")
    state_3d = three_d_projection_engine.build_3d_twin_state()
    print(f"    Total 3D Devices Extracted : {state_3d.totalDevices}")
    print(f"    Total 3D Links Extracted   : {state_3d.totalLinks}")

    assert state_3d.totalDevices == len(attack_path_graph.nodes)
    assert state_3d.totalLinks == len(attack_path_graph.edges)
    print("    [PASS] 3D State mirrors backend Twin graph without duplicate data.")

    # 2. Canonical vs Visual State Decoupling
    print("\n[2/7] Auditing Canonical Domain vs Visual State Decoupling...")
    web_canon = next(d for d in state_3d.devices if d.deviceId == "WEB-01")
    web_vis = state_3d.visualStates["WEB-01"]

    print(f"    Canonical: Hostname={web_canon.hostname} | Ports={web_canon.openPorts} | Risk={web_canon.riskScore}")
    print(f"    Visual   : Archetype={web_vis.archetype.value} | Pos=({web_vis.position.x}, {web_vis.position.y}, {web_vis.position.z})")

    assert web_canon.deviceId == web_vis.deviceId
    assert hasattr(web_vis, "position")
    assert not hasattr(web_canon, "position")  # Canonical domain model remains unpolluted
    print("    [PASS] Clean separation of canonical data and 3D visual metadata.")

    # 3. Device-to-3D Archetype Mapping
    print("\n[3/7] Auditing Device-to-3D Archetype & Fallback Mapping...")
    mappings = {
        "Firewall Appliance": MeshArchetypeEnum.FIREWALL,
        "Core Router": MeshArchetypeEnum.ROUTER,
        "Web Application Server": MeshArchetypeEnum.SERVER,
        "MySQL Relational Database": MeshArchetypeEnum.DATABASE,
        "Internal Workstation Client": MeshArchetypeEnum.CLIENT,
        "Exotic SCADA Controller": MeshArchetypeEnum.GENERIC_DEVICE  # Fallback
    }
    for raw, expected in mappings.items():
        res = DeviceTo3DMapper.map_archetype(raw)
        print(f"    Raw Type: {raw:<32} -> Archetype: {res.value:<16} (Expected: {expected.value})")
        assert res == expected
    print("    [PASS] Archetype mapping and generic fallback verified.")

    # 4. 3D Spatial Node Positioning
    print("\n[4/7] Auditing Spatial Layout Coordinates (Zone Z-Axis Offsets)...")
    for d in state_3d.devices:
        vis = state_3d.visualStates[d.deviceId]
        print(f"    Device: {d.deviceId:<14} Zone: {d.zone:<10} Coordinates: ({vis.position.x:6.1f}, {vis.position.y:4.1f}, {vis.position.z:6.1f})")
        if d.zone == "INTERNET":
            assert vis.position.z == -150.0
        elif d.zone == "DMZ":
            assert vis.position.z == -50.0
        elif d.zone == "INTERNAL":
            assert vis.position.z == 50.0
        elif d.zone == "DATABASE":
            assert vis.position.z == 150.0
    print("    [PASS] Spatial layout respects zone depth boundaries.")

    # 5. 3D Directed Link Projection
    print("\n[5/7] Auditing 3D Network Link Geometry Connections...")
    assert len(state_3d.links) >= 4
    link0 = state_3d.links[0]
    print(f"    Link: {link0.sourceDeviceId} -> {link0.targetDeviceId} ({link0.protocol})")
    print(f"    Source Vector: ({link0.sourcePos.x}, {link0.sourcePos.y}, {link0.sourcePos.z})")
    print(f"    Target Vector: ({link0.targetPos.x}, {link0.targetPos.y}, {link0.targetPos.z})")
    print(f"    Reachable    : {link0.isReachable} | Particles: {link0.trafficParticleCount}")

    assert link0.sourcePos != link0.targetPos
    assert link0.trafficParticleCount > 0
    print("    [PASS] 3D links span source and destination vectors with particle counts.")

    # 6. Selection State Handling
    print("\n[6/7] Auditing Interactive 3D Device Selection State...")
    three_d_projection_engine.selected_device_id = "DB-01"
    sel_state = three_d_projection_engine.build_3d_twin_state()
    assert sel_state.visualStates["DB-01"].isSelected is True
    assert sel_state.visualStates["WEB-01"].isSelected is False
    print("    DB-01 marked isSelected=True, others False.")
    three_d_projection_engine.selected_device_id = None
    print("    [PASS] Selection state properly flags target mesh visual state.")

    # 7. Single Source-of-Truth Mutation Validation
    print("\n[7/7] Auditing Dynamic Propagation of Backend State into 3D View...")
    # Mutate backend node security state
    attack_path_graph.get_node("WEB-01").securityState = "COMPROMISED"
    mutated_3d = three_d_projection_engine.build_3d_twin_state()

    print(f"    WEB-01 3D Emissive Hex: {mutated_3d.visualStates['WEB-01'].emissiveHex}")
    print(f"    WEB-01 Particle Pulse : {mutated_3d.visualStates['WEB-01'].particlePulseRate}x")
    assert mutated_3d.visualStates["WEB-01"].emissiveHex == "#EF4444"
    assert mutated_3d.visualStates["WEB-01"].particlePulseRate == 3.0

    # Reset
    attack_path_graph.get_node("WEB-01").securityState = "AT_RISK"
    print("    [PASS] Backend security state mutations propagate into 3D visuals.")

    print("\n" + "=" * 80)
    print("       ALL DAY 155 3D DIGITAL TWIN ARCHITECTURE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day155_suite()