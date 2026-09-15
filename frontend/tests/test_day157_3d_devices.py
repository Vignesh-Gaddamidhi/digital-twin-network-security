import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from frontend.topology.three_d_twin_contract import MeshArchetypeEnum, DeviceTo3DMapper
from frontend.topology.three_d_scene_models import CameraStateEnum
from frontend.topology.three_d_scene_engine import three_d_scene_engine
from frontend.topology.device_3d_models import SelectionStateEnum, LabelDisplayMode
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine

def run_day157_suite():
    print("=" * 80)
    print("       WEEK 23 - DAY 157: 3D DEVICES, LABELS & SELECTION AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    device_3d_renderer_engine.sync_devices_from_twin()

    # 1. Device Representations & Archetype Mappings
    print("[1/9] Auditing 3D Device Geometry Archetype Mappings & Unknown Fallback...")
    archetypes = [
        ("Internet Gateway", MeshArchetypeEnum.FIREWALL),
        ("Core Edge Router", MeshArchetypeEnum.ROUTER),
        ("Distribution Switch", MeshArchetypeEnum.SWITCH),
        ("Web Application Server", MeshArchetypeEnum.SERVER),
        ("MySQL Database Cluster", MeshArchetypeEnum.DATABASE),
        ("Internal DNS Resolver", MeshArchetypeEnum.DNS),
        ("Workstation PC Client", MeshArchetypeEnum.CLIENT),
        ("Legacy PLC Device", MeshArchetypeEnum.GENERIC_DEVICE)  # Fallback
    ]
    for raw_desc, expected_arch in archetypes:
        mapped = DeviceTo3DMapper.map_archetype(raw_desc)
        print(f"    Raw: {raw_desc:<28} -> Archetype: {mapped.value:<16} (Expected: {expected_arch.value})")
        assert mapped == expected_arch
    print("    [PASS] All 8 device representations + unknown generic fallback verified.")

    # 2. 3D Spatial Positioning
    print("\n[2/9] Auditing Deterministic 3D Spatial Positions (x, y, z)...")
    snap = device_3d_renderer_engine.get_renderer_snapshot()
    assert snap.totalDevicesRendered >= 5
    for did, mesh in snap.devices.items():
        print(f"    Mesh: {did:<14} Zone: {mesh.zone:<10} Archetype: {mesh.archetype.value:<10} Pos: ({mesh.position.x:6.1f}, {mesh.position.y:4.1f}, {mesh.position.z:6.1f})")
        assert mesh.boundingRadius >= 1.5

    web_pos = snap.devices["WEB-01"].position
    db_pos = snap.devices["DB-01"].position
    assert web_pos.z != db_pos.z  # Respects depth tiering
    print("    [PASS] Deterministic coordinates assigned with boundary radii.")

    # 3. World-Space Billboard Labels
    print("\n[3/9] Auditing Billboard Labels Attachment...")
    web_lbl = snap.devices["WEB-01"].label
    print(f"    WEB-01 Label: Hostname={web_lbl.hostname} | Type={web_lbl.deviceType} | IP={web_lbl.ipAddress}")
    print(f"    World Position: ({web_lbl.worldPosition.x}, {web_lbl.worldPosition.y}, {web_lbl.worldPosition.z})")
    assert web_lbl.worldPosition.y == snap.devices["WEB-01"].position.y + 3.0
    assert web_lbl.isVisible is True
    print("    [PASS] Labels maintain relative vertical offset above device meshes.")

    # 4. Label Visibility & Display Modes
    print("\n[4/9] Auditing Label Visibility Toggle & Display Mode Filtering...")
    device_3d_renderer_engine.set_labels_visibility(False)
    assert device_3d_renderer_engine.labels_visible is False
    assert snap.devices["WEB-01"].label.isVisible is False
    print("    Toggled SHOW LABELS -> HIDE LABELS verified.")

    device_3d_renderer_engine.set_labels_visibility(True)
    device_3d_renderer_engine.set_label_display_mode(LabelDisplayMode.FULL_TELEMETRY)
    assert device_3d_renderer_engine.label_mode == LabelDisplayMode.FULL_TELEMETRY
    assert snap.devices["WEB-01"].label.displayMode == LabelDisplayMode.FULL_TELEMETRY
    print("    Updated Display Mode -> FULL_TELEMETRY verified.")
    print("    [PASS] Label visibility and formatting controls validated.")

    # 5. Raycasting Mesh Picking
    print("\n[5/9] Auditing Screen-Space Raycast Mesh Picking Simulation...")
    # Center screen click (640, 360) corresponding to NDC (0.0, 0.0) where WEB-01 sits at x=0, y=0
    picked = device_3d_renderer_engine.raycast_pick_device(screen_x=640.0, screen_y=360.0)
    print(f"    Raycast at Center Screen (640, 360) -> Intersected Device: {picked}")
    assert picked is not None
    assert picked in snap.devices
    print("    [PASS] Raycast picking intersects device bounding spheres.")

    # 6. Device Selection & Non-Mutation Rule
    print("\n[6/9] Auditing Device Selection State & Non-Mutation Verification...")
    risk_before = attack_path_graph.get_node("WEB-01").riskScore
    did, details = device_3d_renderer_engine.select_device("WEB-01", focus_camera=False)
    risk_after = attack_path_graph.get_node("WEB-01").riskScore

    print(f"    Selected Device ID: {did}")
    print(f"    Details: IP={details.ipAddress} | MAC={details.macAddress} | OS={details.os} | Ports={details.ports}")
    print(f"    Twin Risk Before: {risk_before} | Twin Risk After: {risk_after}")

    assert did == "WEB-01"
    assert details.hostname == "web-01.dmz.internal"
    assert 443 in details.ports
    assert risk_before == risk_after  # Underlying Twin remains unmutated
    assert snap.devices["WEB-01"].selectionState == SelectionStateEnum.SELECTED
    print("    [PASS] Selection returns full details without mutating underlying Twin state.")

    # 7. Device Selection with Smooth Camera Focus
    print("\n[7/9] Auditing Device Selection with Camera Focus Trigger...")
    three_d_scene_engine.reset_camera()
    did_focus, _ = device_3d_renderer_engine.select_device("WEB-01", focus_camera=True)
    cam = three_d_scene_engine.camera_config

    print(f"    Selected: {did_focus} | Camera State: {cam.state.value}")
    print(f"    Camera Target Position: ({cam.target.x}, {cam.target.y}, {cam.target.z})")

    assert cam.state == CameraStateEnum.FOCUSED_DEVICE
    assert cam.target.z == snap.devices["WEB-01"].position.z
    assert device_3d_renderer_engine.focused_device_id == "WEB-01"
    print("    [PASS] Camera successfully focuses selected 3D device coordinates.")

    # 8. Deselection Handling
    print("\n[8/9] Auditing Deselection Flow...")
    did_desel, details_desel = device_3d_renderer_engine.select_device(None)
    assert did_desel is None
    assert details_desel is None
    assert device_3d_renderer_engine.selected_device_id is None
    assert snap.devices["WEB-01"].selectionState == SelectionStateEnum.UNSELECTED
    print("    [PASS] Deselection cleanly clears active device and inspection panel.")

    # 9. Hidden Device Selection Immunity
    print("\n[9/9] Auditing Hidden Device Exemption from Raycasting...")
    device_3d_renderer_engine.hide_device("WEB-01")
    assert snap.devices["WEB-01"].selectionState == SelectionStateEnum.HIDDEN

    # Center pick should now ignore hidden WEB-01
    picked_hidden = device_3d_renderer_engine.raycast_pick_device(screen_x=640.0, screen_y=360.0)
    assert picked_hidden != "WEB-01"
    print(f"    Hidden WEB-01 Raycast Result: {picked_hidden} (Exempt from selection)")

    device_3d_renderer_engine.unhide_device("WEB-01")
    assert snap.devices["WEB-01"].selectionState == SelectionStateEnum.UNSELECTED
    print("    [PASS] Hidden devices do not receive accidental raycast selection.")

    print("\n" + "=" * 80)
    print("       ALL DAY 157 3D DEVICES & SELECTION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day157_suite()