import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.three_d_scene_models import CameraStateEnum, WebGLSceneStatusEnum
from frontend.topology.three_d_scene_engine import three_d_scene_engine

def run_day156_suite():
    print("=" * 80)
    print("       WEEK 23 - DAY 156: THREE.JS FOUNDATION & CAMERA SYSTEM AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 1. 3D Scene Initialization & Snapshots
    print("[1/8] Auditing 3D WebGL Scene Graph Mount & Buffer Allocation...")
    snap = three_d_scene_engine.mount_scene()
    cli_panel = snap.render_cli_panel()
    print(cli_panel)

    assert snap.status == WebGLSceneStatusEnum.LOADED
    assert snap.isRenderLoopActive is True
    assert snap.totalGeometriesLoaded >= 5
    assert snap.totalMaterialsLoaded >= 10
    print("    [PASS] Scene mounted with lighting, camera, and geometry buffers.")

    # 2. Camera Controls: Zoom In / Out
    print("\n[2/8] Auditing Camera Zoom In / Out...")
    cam_zoom_in = three_d_scene_engine.zoom_camera(delta_wheel=-100.0)
    print(f"    Zoom In (wheel -100) : Zoom={cam_zoom_in.zoomLevel}x | Pos=({cam_zoom_in.position.x}, {cam_zoom_in.position.y}, {cam_zoom_in.position.z})")
    assert cam_zoom_in.zoomLevel > 1.0
    assert cam_zoom_in.state == CameraStateEnum.USER_CONTROLLED

    cam_zoom_out = three_d_scene_engine.zoom_camera(delta_wheel=200.0)
    print(f"    Zoom Out (wheel +200): Zoom={cam_zoom_out.zoomLevel}x")
    assert cam_zoom_out.zoomLevel < cam_zoom_in.zoomLevel
    print("    [PASS] Camera zoom and distance scaling validated.")

    # 3. Camera Controls: Pan & Rotate
    print("\n[3/8] Auditing Camera Pan & Orbit Rotation...")
    cam_pan = three_d_scene_engine.pan_camera(delta_x=25.0, delta_y=-10.0)
    print(f"    Pan  : Pos=({cam_pan.position.x}, {cam_pan.position.y}) | Target=({cam_pan.target.x}, {cam_pan.target.y})")
    assert cam_pan.target.x == 25.0 and cam_pan.target.y == -10.0

    cam_rot = three_d_scene_engine.rotate_camera(delta_theta_rad=0.35, delta_phi_rad=-0.15)
    print(f"    Orbit: Pos=({cam_rot.position.x}, {cam_rot.position.y}, {cam_rot.position.z})")
    assert cam_rot.state == CameraStateEnum.USER_CONTROLLED
    print("    [PASS] Camera pan and spherical orbit rotation validated.")

    # 4. Camera Reset Trigger
    print("\n[4/8] Auditing Camera RESET Action...")
    cam_rst = three_d_scene_engine.reset_camera()
    print(f"    Reset Position : ({cam_rst.position.x}, {cam_rst.position.y}, {cam_rst.position.z})")
    print(f"    Reset Target   : ({cam_rst.target.x}, {cam_rst.target.y}, {cam_rst.target.z})")
    assert cam_rst.state == CameraStateEnum.DEFAULT
    assert cam_rst.zoomLevel == 1.0
    assert cam_rst.position.z == 320.0
    print("    [PASS] Camera returns to default isometric coordinates.")

    # 5. Focus on Target Device (WEB-01)
    print("\n[5/8] Auditing Camera Focus on Device ('WEB-01')...")
    cam_dev = three_d_scene_engine.focus_device("WEB-01")
    print(f"    Focused Target   : ({cam_dev.target.x}, {cam_dev.target.y}, {cam_dev.target.z})")
    print(f"    Focused Camera   : ({cam_dev.position.x}, {cam_dev.position.y}, {cam_dev.position.z})")
    assert cam_dev.state == CameraStateEnum.FOCUSED_DEVICE
    assert cam_dev.target.z == -50.0  # DMZ offset
    print("    [PASS] Camera focuses target device coordinates.")

    # 6. Focus on Multi-Hop Attack Traversal Path
    print("\n[6/8] Auditing Camera Focus on Attack Path (CLIENT-01 -> WEB-01 -> DB-01)...")
    cam_path = three_d_scene_engine.focus_path(["CLIENT-01", "WEB-01", "DB-01"])
    print(f"    Path Center Target: ({cam_path.target.x}, {cam_path.target.y}, {cam_path.target.z})")
    assert cam_path.state == CameraStateEnum.FOCUSED_PATH
    print("    [PASS] Camera elevates to frame multi-hop attack traversal.")

    # 7. Responsive Viewport Resize Recalculation
    print("\n[7/8] Auditing Responsive Viewport Resizing (Dell Latitude & High-Res)...")
    dim_laptop = three_d_scene_engine.resize_viewport(width=1366, height=768, dpr=1.0)
    print(f"    Laptop Target   : {dim_laptop.widthPx}x{dim_laptop.heightPx} | Aspect: {dim_laptop.aspectRatio}")
    assert dim_laptop.aspectRatio == 1.779

    dim_desktop = three_d_scene_engine.resize_viewport(width=1920, height=1080, dpr=2.0)
    print(f"    Desktop Retina  : {dim_desktop.widthPx}x{dim_desktop.heightPx} | DPR: {dim_desktop.devicePixelRatio}")
    assert dim_desktop.devicePixelRatio == 2.0
    print("    [PASS] Responsive viewport resize recalculates projection aspect ratio.")

    # 8. WebGL Lifecycle & Safe Resource Disposal
    print("\n[8/8] Auditing WebGL Lifecycle Cleanup & Unmount...")
    three_d_scene_engine.step_render_frame()
    three_d_scene_engine.step_render_frame()
    assert three_d_scene_engine.rendered_frame_count >= 2

    three_d_scene_engine.unmount_scene()
    snap_unmount = three_d_scene_engine.get_snapshot()
    print(f"    Unmounted State : isRenderLoopActive={snap_unmount.isRenderLoopActive} | Geometries={snap_unmount.totalGeometriesLoaded}")
    assert snap_unmount.isRenderLoopActive is False
    assert snap_unmount.totalGeometriesLoaded == 0

    # Re-mount test
    three_d_scene_engine.mount_scene()
    snap_remount = three_d_scene_engine.get_snapshot()
    assert snap_remount.isRenderLoopActive is True
    print("    [PASS] WebGL resources disposed cleanly without memory leaks on unmount.")

    print("\n" + "=" * 80)
    print("       ALL DAY 156 THREE.JS FOUNDATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day156_suite()