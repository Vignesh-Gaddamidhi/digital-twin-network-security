from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import math

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.three_d_twin_contract import MeshArchetypeEnum, Vector3D, DeviceTo3DMapper
from frontend.topology.device_3d_models import (
    SelectionStateEnum, LabelDisplayMode, LabelFilterOption, Device3DLabel,
    Device3DMeshMetadata, DeviceInspectionDetail3D, DeviceRendererSnapshot
)
from frontend.topology.three_d_scene_engine import three_d_scene_engine

class Device3DRendererEngine:
    """Manages 3D device geometry meshes, CSS labels, raycasting selection, and camera focus."""

    def __init__(self):
        self.device_mesh_registry: Dict[str, Device3DMeshMetadata] = {}
        self.selected_device_id: Optional[str] = None
        self.focused_device_id: Optional[str] = None
        self.labels_visible: bool = True
        self.label_mode: LabelDisplayMode = LabelDisplayMode.TYPE_AND_HOSTNAME
        self.sync_devices_from_twin()

    def sync_devices_from_twin(self):
        """Builds 3D device mesh representations directly from backend Digital Twin graph."""
        self.device_mesh_registry.clear()
        nodes = attack_path_graph.nodes
        
        zones: Dict[str, List[str]] = {}
        for nid, node in nodes.items():
            z = node.zone.upper()
            zones.setdefault(z, []).append(nid)

        for z, node_ids in zones.items():
            total = len(node_ids)
            for idx, nid in enumerate(node_ids):
                node = nodes[nid]
                dev_raw = twin_graph_synchronizer.device_store.get(nid, {})
                pos = DeviceTo3DMapper.compute_initial_position(z, idx, total)
                archetype = DeviceTo3DMapper.map_archetype(node.deviceType)
                base_color = DeviceTo3DMapper.ARCHETYPE_COLORS.get(archetype, "#9CA3AF")
                ip = node.ipAddresses[0] if node.ipAddresses else dev_raw.get("ip", "10.0.0.1")

                # Label initialization
                lbl = Device3DLabel(
                    deviceId=nid,
                    hostname=node.hostname,
                    deviceType=node.deviceType,
                    ipAddress=ip,
                    riskScore=node.riskScore,
                    securityState=node.securityState,
                    worldPosition=Vector3D(x=pos.x, y=pos.y + 3.0, z=pos.z),
                    isVisible=self.labels_visible,
                    displayMode=self.label_mode
                )

                emissive = "#000000"
                if node.securityState == "COMPROMISED":
                    emissive = "#EF4444"
                elif node.securityState == "AT_RISK":
                    emissive = "#F59E0B"

                meta = Device3DMeshMetadata(
                    deviceId=nid,
                    hostname=node.hostname,
                    archetype=archetype,
                    zone=z,
                    position=pos,
                    boundingRadius=2.0 if archetype in (MeshArchetypeEnum.DATABASE, MeshArchetypeEnum.FIREWALL) else 1.5,
                    selectionState=SelectionStateEnum.SELECTED if nid == self.selected_device_id else SelectionStateEnum.UNSELECTED,
                    baseColorHex=base_color,
                    emissiveColorHex=emissive,
                    isSelectable=True,
                    label=lbl
                )
                self.device_mesh_registry[nid] = meta

    def set_labels_visibility(self, visible: bool) -> bool:
        self.labels_visible = visible
        for d in self.device_mesh_registry.values():
            d.label.isVisible = visible
        return self.labels_visible

    def set_label_display_mode(self, mode: LabelDisplayMode) -> LabelDisplayMode:
        self.label_mode = mode
        for d in self.device_mesh_registry.values():
            d.label.displayMode = mode
        return self.label_mode

    def raycast_pick_device(self, screen_x: float, screen_y: float, viewport_w: int = 1280, viewport_h: int = 720) -> Optional[str]:
        """Simulates camera unprojected raycast intersection against 3D bounding spheres."""
        # Convert screen click to Normalized Device Coordinates (NDC)
        ndc_x = (2.0 * screen_x) / max(1, viewport_w) - 1.0
        ndc_y = 1.0 - (2.0 * screen_y) / max(1, viewport_h)

        closest_device: Optional[str] = None
        closest_distance = float("inf")

        cam_pos = three_d_scene_engine.camera_config.position

        for did, mesh in self.device_mesh_registry.items():
            if mesh.selectionState == SelectionStateEnum.HIDDEN or not mesh.isSelectable:
                continue

            # Simplified raycast test against projected world coordinates
            dx = mesh.position.x - (ndc_x * 80.0)
            dy = mesh.position.y - (ndc_y * 80.0)
            dist_sq = dx*dx + dy*dy

            # Check if within bounding radius tolerance
            if dist_sq <= (mesh.boundingRadius * 4.0)**2:
                # Calculate Euclidean distance to camera
                cdx = mesh.position.x - cam_pos.x
                cdy = mesh.position.y - cam_pos.y
                cdz = mesh.position.z - cam_pos.z
                cam_dist = math.sqrt(cdx*cdx + cdy*cdy + cdz*cdz)
                if cam_dist < closest_distance:
                    closest_distance = cam_dist
                    closest_device = did

        return closest_device

    def select_device(self, device_id: Optional[str], focus_camera: bool = False) -> Tuple[Optional[str], Optional[DeviceInspectionDetail3D]]:
        """Updates selection state across 3D meshes without mutating underlying Twin."""
        # Deselection handler
        if not device_id or device_id not in self.device_mesh_registry:
            for d in self.device_mesh_registry.values():
                if d.selectionState == SelectionStateEnum.SELECTED:
                    d.selectionState = SelectionStateEnum.UNSELECTED
            self.selected_device_id = None
            self.focused_device_id = None
            return None, None

        # Set new selection
        for did, d in self.device_mesh_registry.items():
            if did == device_id:
                d.selectionState = SelectionStateEnum.SELECTED
            elif d.selectionState == SelectionStateEnum.SELECTED:
                d.selectionState = SelectionStateEnum.UNSELECTED

        self.selected_device_id = device_id

        if focus_camera:
            three_d_scene_engine.focus_device(device_id)
            self.focused_device_id = device_id

        # Lookup details from single source of truth
        detail = self.get_device_details(device_id)
        return device_id, detail

    def hover_device(self, device_id: Optional[str]):
        for did, d in self.device_mesh_registry.items():
            if d.selectionState != SelectionStateEnum.SELECTED and d.selectionState != SelectionStateEnum.HIDDEN:
                d.selectionState = SelectionStateEnum.HOVERED if did == device_id else SelectionStateEnum.UNSELECTED

    def hide_device(self, device_id: str):
        if device_id in self.device_mesh_registry:
            self.device_mesh_registry[device_id].selectionState = SelectionStateEnum.HIDDEN
            self.device_mesh_registry[device_id].label.isVisible = False

    def unhide_device(self, device_id: str):
        if device_id in self.device_mesh_registry:
            self.device_mesh_registry[device_id].selectionState = SelectionStateEnum.UNSELECTED
            self.device_mesh_registry[device_id].label.isVisible = self.labels_visible

    def get_device_details(self, device_id: str) -> DeviceInspectionDetail3D:
        node = attack_path_graph.get_node(device_id)
        dev_raw = twin_graph_synchronizer.device_store.get(device_id, {})
        tier = threshold_classifier.classify(node.riskScore)

        return DeviceInspectionDetail3D(
            deviceId=device_id,
            hostname=node.hostname,
            deviceType=node.deviceType,
            ipAddress=node.ipAddresses[0] if node.ipAddresses else "10.0.0.1",
            macAddress=dev_raw.get("mac", "00:1A:2B:3C:4D:00"),
            os=dev_raw.get("os", "Linux / Embedded"),
            interfaces=["eth0", "eth1"] if "ROUTER" in node.deviceType or "FIREWALL" in node.deviceType else ["eth0"],
            services=node.services,
            ports=node.exposedPorts,
            currentState="ACTIVE",
            securityState=node.securityState,
            riskScore=node.riskScore,
            riskLevel=tier,
            vulnerabilitiesCount=len(node.vulnerabilities),
            vulnerabilities=node.vulnerabilities,
            lastUpdated=datetime.now(timezone.utc).isoformat()
        )

    def get_renderer_snapshot(self) -> DeviceRendererSnapshot:
        return DeviceRendererSnapshot(
            totalDevicesRendered=len(self.device_mesh_registry),
            selectedDeviceId=self.selected_device_id,
            focusedDeviceId=self.focused_device_id,
            labelsVisible=self.labels_visible,
            activeLabelDisplayMode=self.label_mode,
            devices=self.device_mesh_registry
        )

device_3d_renderer_engine = Device3DRendererEngine()