from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class CameraStateEnum(str, Enum):
    DEFAULT = "DEFAULT"
    USER_CONTROLLED = "USER_CONTROLLED"
    FOCUSED_DEVICE = "FOCUSED_DEVICE"
    FOCUSED_PATH = "FOCUSED_PATH"
    RESETTING = "RESETTING"

class WebGLSceneStatusEnum(str, Enum):
    LOADING = "LOADING"
    LOADED = "LOADED"
    EMPTY = "EMPTY"
    ERROR = "ERROR"
    REFRESHING = "REFRESHING"
    UNAVAILABLE = "UNAVAILABLE"

class Vector3D(BaseModel):
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0

class CameraConfiguration(BaseModel):
    state: CameraStateEnum = CameraStateEnum.DEFAULT
    position: Vector3D = Field(default_factory=lambda: Vector3D(x=0.0, y=180.0, z=320.0))
    target: Vector3D = Field(default_factory=lambda: Vector3D(x=0.0, y=0.0, z=0.0))
    fov: float = 45.0
    nearPlane: float = 0.1
    farPlane: float = 2000.0
    zoomLevel: float = 1.0
    minDistance: float = 30.0
    maxDistance: float = 800.0

class SceneViewportDimensions(BaseModel):
    widthPx: int = 1280
    heightPx: int = 720
    devicePixelRatio: float = 1.0
    aspectRatio: float = 1.778

class SceneLightingSetup(BaseModel):
    ambientLightColor: str = "#FFFFFF"
    ambientIntensity: float = 0.4
    directionalKeyColor: str = "#60A5FA"
    directionalKeyIntensity: float = 0.8
    directionalKeyPosition: Vector3D = Field(default_factory=lambda: Vector3D(x=100.0, y=200.0, z=150.0))
    hemisphereSkyColor: str = "#1E293B"
    hemisphereGroundColor: str = "#0F172A"
    hemisphereIntensity: float = 0.3

class ThreeDSceneSnapshot(BaseModel):
    sceneId: str = Field(default_factory=lambda: f"SCN3D-{uuid.uuid4().hex[:6].upper()}")
    status: WebGLSceneStatusEnum = WebGLSceneStatusEnum.LOADED
    errorMessage: Optional[str] = None
    camera: CameraConfiguration = Field(default_factory=CameraConfiguration)
    dimensions: SceneViewportDimensions = Field(default_factory=SceneViewportDimensions)
    lighting: SceneLightingSetup = Field(default_factory=SceneLightingSetup)
    isRenderLoopActive: bool = True
    renderedFrameCount: int = 0
    totalGeometriesLoaded: int = 0
    totalMaterialsLoaded: int = 0
    lastRenderTimestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def render_cli_panel(self) -> str:
        cam = self.camera
        dim = self.dimensions
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                  THREE.JS 3D SCENE & CAMERA CONTROLLER                       ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ Status: [{self.status.value:<11}] │ Loop: {'ACTIVE' if self.isRenderLoopActive else 'STOPPED':<8} │ Viewport: {dim.widthPx}x{dim.heightPx} (DPR: {dim.devicePixelRatio:.1f})      ║",
            f"║ Camera State: [{cam.state.value:<15}] │ FOV: {cam.fov:4.1f}° │ Zoom: {cam.zoomLevel:4.2f}x                     ║",
            f"║ Position: ({cam.position.x:6.1f}, {cam.position.y:6.1f}, {cam.position.z:6.1f}) │ Target: ({cam.target.x:5.1f}, {cam.target.y:5.1f}, {cam.target.z:5.1f})       ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ LIGHTING: Ambient: {self.lighting.ambientIntensity:.1f} │ Directional Key: {self.lighting.directionalKeyIntensity:.1f} │ Hemisphere: {self.lighting.hemisphereIntensity:.1f}   ║",
            f"║ BUFFER STATS: Geometries: {self.totalGeometriesLoaded:02d} │ Materials: {self.totalMaterialsLoaded:02d} │ Frames: {self.renderedFrameCount:<10}          ║",
            "╚══════════════════════════════════════════════════════════════════════════════╝"
        ]
        return "\n".join(lines)