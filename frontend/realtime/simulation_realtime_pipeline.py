import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.topology_models import TopologyNodeState
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.simulations.simulation_models import (
    ScenarioIdentifierEnum, SimulationExecutionState, SimulationStageEnum
)
from frontend.simulations.simulation_control_engine import simulation_control_engine
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeEventEnvelope, SimulationStatusPayload,
    TrafficTelemetryPayload, DeviceStatePayload, ThreatTelemetryPayload
)
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager

class SimulationRealtimePipeline:
    """Pipelines simulation execution ticks into canonical Twin mutations and WebSocket dispatches."""

    def __init__(self):
        self.active_scenario = ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE
        self.wall_clock_start = datetime.now(timezone.utc)
        self.simulation_tick_count = 0

    def get_simulation_status_payload(self) -> SimulationStatusPayload:
        sim = simulation_control_engine.live_state
        total_duration = getattr(sim, "totalDurationSeconds", getattr(sim, "durationSeconds", 120))
        return SimulationStatusPayload(
            simulationId=sim.reproducibility.simulationId,
            scenario=sim.activeScenario.value,
            executionState=sim.executionState.value,
            currentStage=sim.currentStage.value,
            elapsedSeconds=sim.elapsedSeconds,
            totalDurationSeconds=total_duration,
            progressPct=getattr(sim, 'progressPct', getattr(sim, 'progressPercent', 0.0))
        )

    async def broadcast_status(self) -> RealtimeEventEnvelope:
        payload = self.get_simulation_status_payload()
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.SIMULATION_STATUS_UPDATE,
            payload=payload.model_dump(),
            simulation_id=payload.simulationId
        )
        await websocket_connection_manager.broadcast_envelope(env)
        return env

    async def start_simulation(
        self,
        scenario: ScenarioIdentifierEnum = ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE,
        duration: Optional[int] = None,
        duration_seconds: Optional[int] = None
    ) -> Dict[str, Any]:
        self.active_scenario = scenario
        self.simulation_tick_count = 0
        self.wall_clock_start = datetime.now(timezone.utc)
        
        dur = duration or duration_seconds or 120
        simulation_control_engine.select_scenario(scenario=scenario, duration_seconds=dur)
        simulation_control_engine.start()
        env = await self.broadcast_status()
        return {"action": "START", "status": env.payload}

    async def pause_simulation(self) -> Dict[str, Any]:
        simulation_control_engine.pause()
        env = await self.broadcast_status()
        return {"action": "PAUSE", "status": env.payload}

    async def resume_simulation(self) -> Dict[str, Any]:
        simulation_control_engine.resume()
        env = await self.broadcast_status()
        return {"action": "RESUME", "status": env.payload}

    async def stop_simulation(self) -> Dict[str, Any]:
        simulation_control_engine.stop()
        env = await self.broadcast_status()
        return {"action": "STOP", "status": env.payload}

    async def reset_simulation(self) -> Dict[str, Any]:
        simulation_control_engine.reset()
        self.simulation_tick_count = 0

        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.sync_links_from_twin()
        link_3d_renderer_engine.clear_all_traffic()

        env = await self.broadcast_status()
        return {"action": "RESET", "status": env.payload}

    async def process_simulation_tick(self, step_seconds: int = 1) -> List[RealtimeEventEnvelope]:
        """Executes a simulation progression tick, mutates canonical Twin state, and emits envelopes."""
        self.simulation_tick_count += 1
        sim = simulation_control_engine.advance_ticks(step_seconds)
        emitted_envelopes: List[RealtimeEventEnvelope] = []

        # 1. Emit Simulation Status Update
        status_env = await self.broadcast_status()
        emitted_envelopes.append(status_env)

        # 2. Compute Scenario-Specific Telemetry Dynamics
        pkt_rate = getattr(sim, "currentPacketsPerSec", 120.0)
        active_conns = getattr(sim, "currentActiveConnections", 42)

        if self.active_scenario == ScenarioIdentifierEnum.TRAFFIC_SPIKE:
            pkt_rate = 1450.0
            active_conns = 507
        elif self.active_scenario == ScenarioIdentifierEnum.PORT_ANOMALY:
            pkt_rate = 320.0
            active_conns = 180
        elif self.active_scenario == ScenarioIdentifierEnum.NORMAL:
            pkt_rate = 115.0
            active_conns = 42

        # 3. Mutate Canonical Twin Traffic & Link Metrics
        first_lid = list(link_3d_renderer_engine.link_registry.keys())[0] if link_3d_renderer_engine.link_registry else "CONN-WEB-DB"
        traffic_payload = TrafficTelemetryPayload(
            linkId=first_lid,
            sourceDeviceId="CLIENT-01",
            destinationDeviceId="WEB-01",
            protocol="HTTPS",
            packetsPerSecond=pkt_rate,
            bytesPerSecond=pkt_rate * 512.0,
            activeConnections=active_conns
        )
        traffic_env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.TRAFFIC_UPDATE,
            payload=traffic_payload.model_dump(),
            device_id="CLIENT-01"
        )
        await websocket_connection_manager.broadcast_envelope(traffic_env)
        emitted_envelopes.append(traffic_env)

        # 4. If in Escalation/Impact stage of attack, mutate Canonical Twin Security State
        stage_val = sim.currentStage.value if hasattr(sim.currentStage, "value") else str(sim.currentStage)
        if (
            self.active_scenario in (ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE, ScenarioIdentifierEnum.EXFILTRATION_LIKE)
            and stage_val in ("ESCALATION", "IMPACT")
        ):
            web_node = attack_path_graph.get_node("WEB-01")
            prev_state = web_node.securityState
            web_node.securityState = "COMPROMISED"
            
            device_3d_renderer_engine.sync_devices_from_twin()

            dev_payload = DeviceStatePayload(
                deviceId="WEB-01",
                previousState=TopologyNodeState.NORMAL if prev_state != "COMPROMISED" else TopologyNodeState.COMPROMISED,
                newState=TopologyNodeState.COMPROMISED,
                reason="Exploitation of CVE-2026-WEB-RCE lateral pivot",
                quarantineEnforced=False
            )
            dev_env = realtime_event_manager.build_envelope(
                event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
                payload=dev_payload.model_dump(),
                device_id="WEB-01"
            )
            await websocket_connection_manager.broadcast_envelope(dev_env)
            emitted_envelopes.append(dev_env)

        return emitted_envelopes

simulation_realtime_pipeline = SimulationRealtimePipeline()