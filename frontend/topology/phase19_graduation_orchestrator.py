from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import time

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator
from frontend.topology.three_d_twin_contract import MeshArchetypeEnum, Vector3D, DeviceTo3DMapper
from frontend.topology.three_d_scene_models import CameraStateEnum, WebGLSceneStatusEnum
from frontend.topology.three_d_scene_engine import three_d_scene_engine
from frontend.topology.device_3d_models import SelectionStateEnum, LabelDisplayMode
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_models import LinkStateEnum, TrafficFlowDirectionEnum, TrafficProtocolType
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.topology.security_3d_models import TopologyNodeState
from frontend.topology.security_3d_renderer_engine import security_3d_renderer_engine
from frontend.topology.three_d_filter_models import (
    ViewModeEnum, VisibilityPresetEnum, TopologyFilterCriteria
)
from frontend.topology.three_d_navigation_engine import three_d_navigation_engine

class Phase19GraduationOrchestrator:
    """Master orchestrator executing complete 3D integration verification, performance profiling, and E2E lifecycles."""

    def run_e2e_security_scenario(self) -> Dict[str, Any]:
        """Runs the complete E2E scenario from baseline through compromise, isolation, and recovery."""
        # 1. Baseline initialization
        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.sync_links_from_twin()
        three_d_navigation_engine.sync_attack_paths()

        step1_devices = len(device_3d_renderer_engine.device_mesh_registry)
        step1_links = len(link_3d_renderer_engine.link_registry)

        # 2. Traffic Spike Injection
        first_lid = list(link_3d_renderer_engine.link_registry.keys())[0]
        for _ in range(50):
            link_3d_renderer_engine.inject_traffic_flow(first_lid, protocol=TrafficProtocolType.HTTPS)
        step2_particles = link_3d_renderer_engine.get_snapshot().totalActiveParticles

        # 3. Detection & Security State Transition -> WEB-01 COMPROMISED
        attack_path_graph.get_node("WEB-01").securityState = "COMPROMISED"
        security_vis = security_3d_renderer_engine.get_device_security_visual("WEB-01")
        step3_halo = security_vis.haloColorHex
        step3_beacon = security_vis.hasThreatBeacon

        # 4. Attack Path Discovery & 3D Highlighting
        paths = list(three_d_navigation_engine.cached_attack_paths.keys())
        highlighted_path_id = paths[0] if paths else None
        if highlighted_path_id:
            three_d_navigation_engine.select_attack_path_3d(highlighted_path_id)
        step4_highlighted = device_3d_renderer_engine.device_mesh_registry["WEB-01"].isHighlighted

        # 5. Simulated Response: Quarantine CLIENT-01
        twin_graph_synchronizer.isolate_device("CLIENT-01")
        client_vis = security_3d_renderer_engine.get_device_security_visual("CLIENT-01")
        step5_cage = client_vis.hasIsolationCage

        # 6. Recovery: Restore baseline
        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.clear_all_traffic()
        three_d_navigation_engine.select_attack_path_3d(None)
        step6_restored_state = attack_path_graph.get_node("WEB-01").securityState

        return {
            "initialDevices": step1_devices,
            "initialLinks": step1_links,
            "trafficSpikeParticles": step2_particles,
            "compromisedHaloColor": step3_halo,
            "threatBeaconActive": step3_beacon,
            "attackPathHighlighted": step4_highlighted,
            "isolationCageActive": step5_cage,
            "restoredState": step6_restored_state
        }

    def profile_scalability_and_limits(self) -> Dict[str, Any]:
        """Profiles device scaling limits, link loads, and particle buffer clamping."""
        results = {}

        # 1. Device Scaling Timing (Simulated layout coordinate calculation)
        for count in [10, 25, 50, 100]:
            t0 = time.perf_counter()
            for i in range(count):
                _ = DeviceTo3DMapper.compute_initial_position("INTERNAL", i, count)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            results[f"deviceLayout_{count}_nodes_ms"] = round(elapsed_ms, 3)

        # 2. Traffic Particle Clamping Test (500 and 1,000 events)
        link_3d_renderer_engine.clear_all_traffic()
        target_lid = list(link_3d_renderer_engine.link_registry.keys())[0]

        # 500 events
        for _ in range(500):
            link_3d_renderer_engine.inject_traffic_flow(target_lid)
        count_at_500 = link_3d_renderer_engine.get_snapshot().totalActiveParticles

        # 500 more events (total 1000)
        for _ in range(500):
            link_3d_renderer_engine.inject_traffic_flow(target_lid)
        count_at_1000 = link_3d_renderer_engine.get_snapshot().totalActiveParticles

        results["particlesAt500Injections"] = count_at_500
        results["particlesAt1000Injections"] = count_at_1000
        results["clampedUnderLimit"] = (count_at_1000 <= link_3d_renderer_engine.max_particle_capacity)

        link_3d_renderer_engine.clear_all_traffic()
        return results

    def audit_memory_lifecycle(self) -> Dict[str, Any]:
        """Tests WebGL buffer mounting, unmounting, and resource deallocation."""
        three_d_scene_engine.mount_scene()
        snap_mounted = three_d_scene_engine.get_snapshot()

        # Allocate particles
        target_lid = list(link_3d_renderer_engine.link_registry.keys())[0]
        for _ in range(20):
            link_3d_renderer_engine.inject_traffic_flow(target_lid)

        # Execute unmount / cleanup
        three_d_scene_engine.unmount_scene()
        link_3d_renderer_engine.clear_all_traffic()
        snap_unmounted = three_d_scene_engine.get_snapshot()

        # Remount
        three_d_scene_engine.mount_scene()
        snap_remounted = three_d_scene_engine.get_snapshot()

        return {
            "initialGeometries": snap_mounted.totalGeometriesLoaded,
            "unmountedGeometries": snap_unmounted.totalGeometriesLoaded,
            "unmountedLoopActive": snap_unmounted.isRenderLoopActive,
            "particlesAfterClear": link_3d_renderer_engine.get_snapshot().totalActiveParticles,
            "remountedGeometries": snap_remounted.totalGeometriesLoaded,
            "lifecycleClean": (snap_unmounted.totalGeometriesLoaded == 0 and not snap_unmounted.isRenderLoopActive)
        }

phase19_graduation_orchestrator = Phase19GraduationOrchestrator()