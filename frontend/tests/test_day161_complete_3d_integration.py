import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from frontend.topology.phase19_graduation_orchestrator import phase19_graduation_orchestrator
from frontend.topology.three_d_twin_contract import MeshArchetypeEnum, DeviceTo3DMapper
from frontend.topology.three_d_scene_engine import three_d_scene_engine
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.topology.security_3d_renderer_engine import security_3d_renderer_engine
from frontend.topology.three_d_navigation_engine import three_d_navigation_engine

def run_day161_suite():
    print("=" * 80)
    print("       WEEK 23 - DAY 161: MASTER 3D DIGITAL TWIN INTEGRATION AUDIT")
    print("================================================================================" + "\n")

    # 1. Full Data Flow Integrity Verification
    print("[1/8] Auditing Unified 3D Data Flow from Digital Twin Single Source of Truth...")
    snap_3d = three_d_scene_engine.mount_scene()
    dev_snap = device_3d_renderer_engine.get_renderer_snapshot()
    link_snap = link_3d_renderer_engine.get_snapshot()
    sec_snap = security_3d_renderer_engine.get_snapshot()

    print(f"    Devices Mounted : {dev_snap.totalDevicesRendered}")
    print(f"    Links Mounted   : {link_snap.totalLinks}")
    print(f"    Security Visuals: {sec_snap.totalDevices}")

    assert dev_snap.totalDevicesRendered >= 5
    assert link_snap.totalLinks >= 4
    assert sec_snap.totalDevices == dev_snap.totalDevicesRendered
    print("    [PASS] Unified 3D scene data flow matches Digital Twin state.")

    # 2. Archetype & Unknown Device Fallback
    print("\n[2/8] Auditing Device Archetype Renderers & Fallback Safety...")
    known_arch = DeviceTo3DMapper.map_archetype("Core Router")
    unknown_arch = DeviceTo3DMapper.map_archetype("Unrecognized Legacy Appliance")
    print(f"    Known Archetype   : {known_arch.value}")
    print(f"    Fallback Archetype: {unknown_arch.value}")

    assert known_arch == MeshArchetypeEnum.ROUTER
    assert unknown_arch == MeshArchetypeEnum.GENERIC_DEVICE
    print("    [PASS] Device representations and unknown fallback confirmed.")

    # 3. Memory Lifecycle & Safe Disposal
    print("\n[3/8] Auditing WebGL Buffer Lifecycle & Memory Deallocation...")
    mem_audit = phase19_graduation_orchestrator.audit_memory_lifecycle()
    print(f"    Mounted Geometries   : {mem_audit['initialGeometries']}")
    print(f"    Unmounted Geometries : {mem_audit['unmountedGeometries']}")
    print(f"    Unmounted Loop Active: {mem_audit['unmountedLoopActive']}")
    print(f"    Remounted Geometries : {mem_audit['remountedGeometries']}")

    assert mem_audit["lifecycleClean"] is True
    assert mem_audit["remountedGeometries"] > 0
    print("    [PASS] WebGL resources and particle systems disposed cleanly without leaks.")

    # 4. Scalability & Particle Clamping
    print("\n[4/8] Auditing Hardware Scalability & Particle Buffer Clamping...")
    scale_audit = phase19_graduation_orchestrator.profile_scalability_and_limits()
    for k, v in scale_audit.items():
        if "deviceLayout" in k:
            print(f"    {k:<32}: {v:6.3f} ms")
    print(f"    Particles under 500 events : {scale_audit['particlesAt500Injections']}")
    print(f"    Particles under 1000 events: {scale_audit['particlesAt1000Injections']} (Limit: 500)")

    assert scale_audit["clampedUnderLimit"] is True
    assert scale_audit["particlesAt1000Injections"] == 500
    print("    [PASS] Hard ceiling on particle allocations prevents browser freezing.")

    # 5. Error Recovery Resilience
    print("\n[5/8] Auditing Graceful Error Recovery & Missing Data Handling...")
    trapped_missing_device = False
    try:
        device_3d_renderer_engine.get_device_details("NON_EXISTENT_HOST_404")
    except KeyError:
        trapped_missing_device = True

    assert trapped_missing_device is True
    print("    [PASS] Invalid identifiers trapped gracefully without canvas collapse.")

    # 6. Epistemic Provenance Integrity
    print("\n[6/8] Auditing Epistemic Provenance Distinction (REAL vs SIMULATION vs PREDICTED)...")
    for did, vis in sec_snap.securityVisuals.items():
        assert hasattr(vis, "provenance")
        assert vis.provenance.value in ("REAL_TELEMETRY", "SIMULATION", "PREDICTED")
    print(f"    Verified provenance tracking across all {sec_snap.totalDevices} 3D nodes.")
    print("    [PASS] Ground truth provenance strictly demarcated.")

    # 7. Complete End-to-End Security Traversal Lifecycle
    print("\n[7/8] Auditing Full End-to-End Security Traversal Lifecycle...")
    scenario_res = phase19_graduation_orchestrator.run_e2e_security_scenario()
    print(f"    1. Initial Mesh Count          : {scenario_res['initialDevices']} devices, {scenario_res['initialLinks']} links")
    print(f"    2. Injected Traffic Particles  : {scenario_res['trafficSpikeParticles']}")
    print(f"    3. Compromised Halo Color      : {scenario_res['compromisedHaloColor']}")
    print(f"    4. Threat Beacon Active        : {scenario_res['threatBeaconActive']}")
    print(f"    5. Attack Path Highlighted     : {scenario_res['attackPathHighlighted']}")
    print(f"    6. Quarantine Isolation Cage   : {scenario_res['isolationCageActive']}")
    print(f"    7. Post-Recovery Restored State: {scenario_res['restoredState']}")

    assert scenario_res["compromisedHaloColor"] == "#EF4444"
    assert scenario_res["threatBeaconActive"] is True
    assert scenario_res["isolationCageActive"] is True
    assert scenario_res["restoredState"] in ("NORMAL", "MONITORED", "AT_RISK")
    print("    [PASS] Complete E2E simulation scenario traversed and restored cleanly.")

    # 8. Full Week 23 System Milestone Check
    print("\n[8/8] Auditing Week 23 Architectural Milestone Invariants...")
    # Invariant: 2D and 3D views project the identical Twin state
    twin_node = attack_path_graph.get_node("WEB-01")
    vis_3d = device_3d_renderer_engine.device_mesh_registry["WEB-01"]
    assert twin_node.hostname == vis_3d.hostname
    print(f"    Single Source of Truth Invariant Confirmed: {twin_node.hostname} (Twin) == {vis_3d.hostname} (3D)")
    print("    [PASS] Week 23 Enterprise 3D Digital Twin verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 161 MASTER 3D INTEGRATION TESTS PASSED CLEANLY")
    print("       PHASE 19 GRADUATED SUCCESSFULLY Ã¢â‚¬â€ READY FOR WEEK 23 MILESTONE TAGGING")
    print("================================================================================")

if __name__ == "__main__":
    run_day161_suite()