import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from frontend.simulations.simulation_models import (
    SimulationExecutionState, SimulationStageEnum, ScenarioIdentifierEnum
)
from frontend.simulations.simulation_control_engine import simulation_control_engine
from frontend.topology.link_3d_models import TrafficProtocolType, TrafficFlowDirectionEnum
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.security_3d_renderer_engine import security_3d_renderer_engine
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeEventEnvelope, SimulationStatusPayload,
    TrafficTelemetryPayload, DeviceStatePayload, ThreatTelemetryPayload,
    RiskTelemetryPayload
)
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager

class SimulationRealtimePipeline:
    """Orchestrates simulation execution, twin state mutation, and WebSocket event distribution."""

    def __init__(self):
        self.is_streaming = False
        self._stream_task: Optional[asyncio.Task] = None
        self.tick_counter = 0

    def get_simulation_status_payload(self) -> SimulationStatusPayload:
        sim = simulation_control_engine.live_state
        return SimulationStatusPayload(
            simulationId=sim.reproducibility.simulationId,
            scenario=sim.activeScenario.value if hasattr(sim.activeScenario, "value") else str(sim.activeScenario),
            executionState=sim.executionState.value,
            currentStage=sim.currentStage.value,
            elapsedSeconds=sim.elapsedSeconds,
            totalDurationSeconds=sim.totalSeconds,
            progressPct=sim.progressPercent
        )

    async def broadcast_simulation_status(self) -> RealtimeEventEnvelope:
        payload = self.get_simulation_status_payload()
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.SIMULATION_STATUS_UPDATE,
            payload=payload.model_dump(),
            simulation_id=payload.simulationId,
            source="SIMULATION_CONTROL_ENGINE"
        )
        await websocket_connection_manager.broadcast_envelope(env)
        return env

    async def start_simulation(self, scenario: Optional[ScenarioIdentifierEnum] = None, duration: int = 120) -> SimulationStatusPayload:
        if scenario:
            simulation_control_engine.select_scenario(scenario=scenario, duration_seconds=duration)
        simulation_control_engine.start()
        await self.broadcast_simulation_status()
        return self.get_simulation_status_payload()

    async def pause_simulation(self) -> SimulationStatusPayload:
        simulation_control_engine.pause()
        await self.broadcast_simulation_status()
        return self.get_simulation_status_payload()

    async def resume_simulation(self) -> SimulationStatusPayload:
        simulation_control_engine.resume()
        await self.broadcast_simulation_status()
        return self.get_simulation_status_payload()

    async def stop_simulation(self) -> SimulationStatusPayload:
        simulation_control_engine.stop()
        await self.broadcast_simulation_status()
        return self.get_simulation_status_payload()

    async def reset_simulation(self) -> SimulationStatusPayload:
        simulation_control_engine.reset()
        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.sync_links_from_twin()
        link_3d_renderer_engine.clear_all_traffic()
        await self.broadcast_simulation_status()
        return self.get_simulation_status_payload()

    async def process_simulation_tick(self, step_seconds: int = 1) -> List[RealtimeEventEnvelope]:
        """Advances simulation ticks, mutates Canonical Twin, and broadcasts delta envelopes."""
        sim = simulation_control_engine.advance_ticks(step_seconds)
        self.tick_counter += 1
        emitted_envelopes: List[RealtimeEventEnvelope] = []

        # 1. Status Update Envelope
        status_env = await self.broadcast_simulation_status()
        emitted_envelopes.append(status_env)

        # 2. Traffic Flow Generation & Twin State Mutation
        links = list(attack_path_graph.edges.keys())
        if links:
            target_lid = links[self.tick_counter % len(links)]
            edge = attack_path_graph.edges[target_lid]
            u, v = edge.sourceNode, edge.destinationNode

            # Determine traffic parameters from simulation scenario
            pkt_rate = sim.currentPacketsPerSec
            byte_rate = pkt_rate * 840.0
            proto = TrafficProtocolType.HTTPS if edge.destinationPort == 443 else TrafficProtocolType.TCP

            # Inject into 3D particle renderer
            link_3d_renderer_engine.inject_traffic_flow(
                link_id=target_lid,
                protocol=proto,
                bytes_count=int(byte_rate / max(1.0, pkt_rate))
            )

            # Broadcast TRAFFIC_UPDATE envelope
            traffic_payload = TrafficTelemetryPayload(
                linkId=target_lid,
                sourceDeviceId=u,
                destinationDeviceId=v,
                protocol=proto,
                packetsPerSecond=round(pkt_rate, 1),
                bytesPerSecond=round(byte_rate, 1),
                activeConnections=int(pkt_rate * 0.35)
            )
            t_env = realtime_event_manager.build_envelope(
                event_type=RealtimeEventType.TRAFFIC_UPDATE,
                payload=traffic_payload.model_dump(),
                device_id=u
            )
            await websocket_connection_manager.broadcast_envelope(t_env)
            emitted_envelopes.append(t_env)

        # 3. Handle Scenario Escalation and Twin Security State Mutations
        if sim.currentStage in (SimulationStageEnum.ESCALATION, SimulationStageEnum.IMPACT):
            # Mutate WEB-01 security state to AT_RISK or COMPROMISED
            target_node = attack_path_graph.get_node("WEB-01")
            prev_st = target_node.securityState
            new_st = "COMPROMISED" if sim.currentStage == SimulationStageEnum.IMPACT else "AT_RISK"

            if prev_st != new_st:
                target_node.securityState = new_st
                device_3d_renderer_engine.device_mesh_registry["WEB-01"].emissiveColorHex = "#EF4444"

                # Broadcast DEVICE_STATE_UPDATE envelope
                dev_payload = DeviceStatePayload(
                    deviceId="WEB-01",
                    previousState=prev_st,
                    newState=new_st,
                    reason=f"Simulation scenario '{sim.activeScenario.value}' entered {sim.currentStage.value}",
                    quarantineEnforced=False
                )
                dev_env = realtime_event_manager.build_envelope(
                    event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
                    payload=dev_payload.model_dump(),
                    deviceId="WEB-01"
                )
                await websocket_connection_manager.broadcast_envelope(dev_env)
                emitted_envelopes.append(dev_env)

                # Broadcast RISK_UPDATE envelope
                tier = threshold_classifier.classify(sim.networkRiskScore)
                risk_payload = RiskTelemetryPayload(
                    targetDeviceId="WEB-01",
                    compositeRiskScore=sim.networkRiskScore,
                    riskLevel=tier,
                    threatProbability=sim.predictedThreatProb,
                    assetCriticality=target_node.assetCriticality,
                    vulnerabilityFactor=0.85,
                    attackImpact=1.0 if target_node.assetCriticality == "CRITICAL" else 0.6
                )
                risk_env = realtime_event_manager.build_envelope(
                    event_type=RealtimeEventType.RISK_UPDATE,
                    payload=risk_payload.model_dump(),
                    deviceId="WEB-01"
                )
                await websocket_connection_manager.broadcast_envelope(risk_env)
                emitted_envelopes.append(risk_env)

        return emitted_envelopes

simulation_realtime_pipeline = SimulationRealtimePipeline()
