from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import math

from frontend.topology.three_d_scene_models import (
    CameraStateEnum, WebGLSceneStatusEnum, Vector3D, CameraConfiguration,
    SceneViewportDimensions, SceneLightingSetup, ThreeDSceneSnapshot
)
from frontend.topology.three_d_projection_engine import three_d_projection_engine

class ThreeDSceneEngine:
    """Manages WebGL rendering environment, camera state transitions, controls, and disposal."""

    DEFAULT_CAMERA_POS = Vector3D(x=0.0, y=180.0, z=320.0)
    DEFAULT_CAMERA_TARGET = Vector3D(x=0.0, y=0.0, z=0.0)

    def __init__(self):
        self.camera_config = CameraConfiguration()
        self.dimensions = SceneViewportDimensions()
        self.lighting = SceneLightingSetup()
        self.status = WebGLSceneStatusEnum.LOADED
        self.error_message: Optional[str] = None
        self.is_render_loop_active = True
        self.rendered_frame_count = 0
        self.allocated_geometries = 0
        self.allocated_materials = 0
        self.mount_scene()

    def mount_scene(self) -> ThreeDSceneSnapshot:
        self.is_render_loop_active = True
        self.status = WebGLSceneStatusEnum.LOADED
        self.error_message = None
        self.camera_config.state = CameraStateEnum.DEFAULT
        self.camera_config.position = self.DEFAULT_CAMERA_POS.model_copy()
        self.camera_config.target = self.DEFAULT_CAMERA_TARGET.model_copy()
        self.camera_config.zoomLevel = 1.0

        # Sync geometries from projection engine
        twin_3d = three_d_projection_engine.build_3d_twin_state()
        self.allocated_geometries = twin_3d.totalDevices + twin_3d.totalLinks
        self.allocated_materials = twin_3d.totalDevices * 2 + twin_3d.totalLinks
        return self.get_snapshot()

    def unmount_scene(self):
        """Releases all WebGL buffers and stops render loops."""
        self.is_render_loop_active = False
        self.allocated_geometries = 0
        self.allocated_materials = 0
        self.status = WebGLSceneStatusEnum.UNAVAILABLE

    def zoom_camera(self, delta_wheel: float) -> CameraConfiguration:
        self.camera_config.state = CameraStateEnum.USER_CONTROLLED
        factor = 1.0 - (delta_wheel * 0.001)
        new_zoom = max(0.2, min(5.0, self.camera_config.zoomLevel * factor))
        self.camera_config.zoomLevel = round(new_zoom, 2)
        
        # Scale distance from target
        dx = self.camera_config.position.x - self.camera_config.target.x
        dy = self.camera_config.position.y - self.camera_config.target.y
        dz = self.camera_config.position.z - self.camera_config.target.z
        
        self.camera_config.position.x = round(self.camera_config.target.x + dx / factor, 1)
        self.camera_config.position.y = round(self.camera_config.target.y + dy / factor, 1)
        self.camera_config.position.z = round(self.camera_config.target.z + dz / factor, 1)
        return self.camera_config.model_copy()

    def pan_camera(self, delta_x: float, delta_y: float) -> CameraConfiguration:
        self.camera_config.state = CameraStateEnum.USER_CONTROLLED
        self.camera_config.position.x = round(self.camera_config.position.x + delta_x, 1)
        self.camera_config.position.y = round(self.camera_config.position.y + delta_y, 1)
        self.camera_config.target.x = round(self.camera_config.target.x + delta_x, 1)
        self.camera_config.target.y = round(self.camera_config.target.y + delta_y, 1)
        return self.camera_config.model_copy()

    def rotate_camera(self, delta_theta_rad: float, delta_phi_rad: float) -> CameraConfiguration:
        self.camera_config.state = CameraStateEnum.USER_CONTROLLED
        # Spherical orbital rotation around current target
        dx = self.camera_config.position.x - self.camera_config.target.x
        dy = self.camera_config.position.y - self.camera_config.target.y
        dz = self.camera_config.position.z - self.camera_config.target.z
        radius = math.sqrt(dx*dx + dy*dy + dz*dz) or 1.0

        current_theta = math.atan2(dx, dz)
        current_phi = math.acos(max(-1.0, min(1.0, dy / radius)))

        new_theta = current_theta + delta_theta_rad
        new_phi = max(0.1, min(math.pi - 0.1, current_phi + delta_phi_rad))

        self.camera_config.position.x = round(self.camera_config.target.x + radius * math.sin(new_phi) * math.sin(new_theta), 1)
        self.camera_config.position.y = round(self.camera_config.target.y + radius * math.cos(new_phi), 1)
        self.camera_config.position.z = round(self.camera_config.target.z + radius * math.sin(new_phi) * math.cos(new_theta), 1)
        return self.camera_config.model_copy()

    def reset_camera(self) -> CameraConfiguration:
        self.camera_config.state = CameraStateEnum.RESETTING
        self.camera_config.position = self.DEFAULT_CAMERA_POS.model_copy()
        self.camera_config.target = self.DEFAULT_CAMERA_TARGET.model_copy()
        self.camera_config.zoomLevel = 1.0
        self.camera_config.state = CameraStateEnum.DEFAULT
        return self.camera_config.model_copy()

    def focus_device(self, device_id: str) -> CameraConfiguration:
        twin_3d = three_d_projection_engine.build_3d_twin_state()
        if device_id not in twin_3d.visualStates:
            raise KeyError(f"Device '{device_id}' not found in 3D scene.")

        pos = twin_3d.visualStates[device_id].position
        self.camera_config.state = CameraStateEnum.FOCUSED_DEVICE
        self.camera_config.target = pos.model_copy()
        self.camera_config.position = Vector3D(x=pos.x, y=pos.y + 40.0, z=pos.z + 65.0)
        self.camera_config.zoomLevel = 1.5
        return self.camera_config.model_copy()

    def focus_path(self, node_sequence: List[str]) -> CameraConfiguration:
        twin_3d = three_d_projection_engine.build_3d_twin_state()
        positions = [twin_3d.visualStates[nid].position for nid in node_sequence if nid in twin_3d.visualStates]
        if not positions:
            return self.reset_camera()

        avg_x = sum(p.x for p in positions) / len(positions)
        avg_y = sum(p.y for p in positions) / len(positions)
        avg_z = sum(p.z for p in positions) / len(positions)

        self.camera_config.state = CameraStateEnum.FOCUSED_PATH
        self.camera_config.target = Vector3D(x=round(avg_x, 1), y=round(avg_y, 1), z=round(avg_z, 1))
        self.camera_config.position = Vector3D(x=round(avg_x, 1), y=round(avg_y + 160.0, 1), z=round(avg_z + 240.0, 1))
        self.camera_config.zoomLevel = 1.2
        return self.camera_config.model_copy()

    def resize_viewport(self, width: int, height: int, dpr: float = 1.0) -> SceneViewportDimensions:
        h = max(1, height)
        self.dimensions = SceneViewportDimensions(
            widthPx=width,
            heightPx=height,
            devicePixelRatio=dpr,
            aspectRatio=round(width / h, 3)
        )
        return self.dimensions

    def set_scene_status(self, status: WebGLSceneStatusEnum, err: Optional[str] = None):
        self.status = status
        self.error_message = err

    def step_render_frame(self) -> int:
        if self.is_render_loop_active:
            self.rendered_frame_count += 1
        return self.rendered_frame_count

    def get_snapshot(self) -> ThreeDSceneSnapshot:
        return ThreeDSceneSnapshot(
            status=self.status,
            errorMessage=self.error_message,
            camera=self.camera_config,
            dimensions=self.dimensions,
            lighting=self.lighting,
            isRenderLoopActive=self.is_render_loop_active,
            renderedFrameCount=self.rendered_frame_count,
            totalGeometriesLoaded=self.allocated_geometries,
            totalMaterialsLoaded=self.allocated_materials,
            lastRenderTimestamp=datetime.now(timezone.utc).isoformat()
        )

three_d_scene_engine = ThreeDSceneEngine()