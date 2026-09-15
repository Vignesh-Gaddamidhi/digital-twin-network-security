import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from frontend.simulations.simulation_models import ScenarioIdentifierEnum, SimulationExecutionState
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.simulation_realtime_pipeline import simulation_realtime_pipeline

class MockPipelineWebSocket:
    def __init__(self, name: str):
        self.name = name
        self.received = []

    async def accept(self):
        pass

    async def send_json(self, data: dict):
        self.received.append(data)

def run_day164_suite():
    print("=" * 80)
    print("       WEEK 24 - DAY 164: SIMULATION REAL-TIME PIPELINE AUDIT")
    print("=" * 80 + "\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def test_body():
        # Setup mock subscriber
        client_ws = MockPipelineWebSocket("test-subscriber")
        await websocket_connection_manager.connect(client_ws)

        # 1. Start Simulation Lifecycle
        print("[1/9] Auditing Simulation START & Status Broadcast...")
        status_start = await simulation_realtime_pipeline.start_simulation(
            scenario=ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE,
            duration=120
        )
        print(f"    Execution State: {status_start.executionState} | Scenario: {status_start.scenario}")
        assert status_start.executionState == "RUNNING"

        # Verify broadcast envelope
        last_msg = client_ws.received[-1]
        assert last_msg["envelope"]["eventType"] == RealtimeEventType.SIMULATION_STATUS_UPDATE.value
        assert last_msg["envelope"]["payload"]["executionState"] == "RUNNING"
        print("    [PASS] Simulation START broadcasts SIMULATION_STATUS_UPDATE.")

        # 2. Pause & Resume Controls
        print("\n[2/9] Auditing Simulation PAUSE & RESUME Controls...")
        status_pause = await simulation_realtime_pipeline.pause_simulation()
        assert status_pause.executionState == "PAUSED"
        assert client_ws.received[-1]["envelope"]["payload"]["executionState"] == "PAUSED"
        print("    PAUSE action verified.")

        status_resume = await simulation_realtime_pipeline.resume_simulation()
        assert status_resume.executionState == "RUNNING"
        assert client_ws.received[-1]["envelope"]["payload"]["executionState"] == "RUNNING"
        print("    RESUME action verified.")
        print("    [PASS] Simulation lifecycle pause and resume controls verified.")

        # 3. Stop & Reset Controls
        print("\n[3/9] Auditing Simulation STOP & RESET Controls...")
        status_stop = await simulation_realtime_pipeline.stop_simulation()
        assert status_stop.executionState == "STOPPED"
        print("    STOP action verified.")

        status_reset = await simulation_realtime_pipeline.reset_simulation()
        assert status_reset.executionState == "IDLE"
        assert status_reset.elapsedSeconds == 0
        print("    RESET action restored clean baseline.")
        print("    [PASS] Simulation lifecycle stop and reset controls verified.")

        # 4. Normal Traffic Streaming
        print("\n[4/9] Auditing Normal Telemetry Flow Emission (TCP/HTTPS)...")
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.NORMAL)
        envelopes_normal = await simulation_realtime_pipeline.process_simulation_tick(step_seconds=1)

        types_emitted = [e.eventType for e in envelopes_normal]
        print(f"    Emitted Event Types: {[t.value for t in types_emitted]}")
        assert RealtimeEventType.TRAFFIC_UPDATE in types_emitted

        traffic_env = next(e for e in envelopes_normal if e.eventType == RealtimeEventType.TRAFFIC_UPDATE)
        print(f"    Traffic Flow: {traffic_env.payload['sourceDeviceId']} -> {traffic_env.payload['destinationDeviceId']} ({traffic_env.payload['packetsPerSecond']} pkt/s)")
        assert traffic_env.payload["packetsPerSecond"] > 0
        print("    [PASS] Normal traffic events stream over WebSocket.")

        # 5. Volumetric Traffic Spike Scenario
        print("\n[5/9] Auditing Volumetric TRAFFIC_SPIKE Scenario...")
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.TRAFFIC_SPIKE)
        # Advance 20 seconds into escalation
        envelopes_spike = await simulation_realtime_pipeline.process_simulation_tick(step_seconds=20)
        spike_env = next(e for e in envelopes_spike if e.eventType == RealtimeEventType.TRAFFIC_UPDATE)

        print(f"    Spike Packet Rate : {spike_env.payload['packetsPerSecond']} pkt/s")
        print(f"    Active Connections: {spike_env.payload['activeConnections']}")
        assert spike_env.payload["packetsPerSecond"] >= 300.0
        print("    [PASS] Volumetric traffic surge correctly reflected in stream.")

        # 6. Port Anomaly Scenario Execution
        print("\n[6/9] Auditing Reconnaissance PORT_ANOMALY Scenario...")
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.PORT_ANOMALY)
        envelopes_port = await simulation_realtime_pipeline.process_simulation_tick(step_seconds=15)
        assert len(envelopes_port) >= 2
        print(f"    Emitted {len(envelopes_port)} events during port anomaly tick.")
        print("    [PASS] PORT_ANOMALY scenario executed and broadcast.")

        # 7. Non-Bypass Invariant & Digital Twin Mutation
        print("\n[7/9] Auditing Canonical Twin Mutation (Non-Bypass Invariant)...")
        # Run LATERAL_MOVEMENT_LIKE into IMPACT stage (tick 75s)
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE)
        envelopes_impact = await simulation_realtime_pipeline.process_simulation_tick(step_seconds=75)

        twin_node = attack_path_graph.get_node("WEB-01")
        print(f"    Canonical Twin WEB-01 State: {twin_node.securityState}")
        assert twin_node.securityState == "COMPROMISED"

        # Verify DEVICE_STATE_UPDATE and RISK_UPDATE were emitted
        assert any(e.eventType == RealtimeEventType.DEVICE_STATE_UPDATE for e in envelopes_impact)
        assert any(e.eventType == RealtimeEventType.RISK_UPDATE for e in envelopes_impact)
        print("    [PASS] Simulation directly mutates Canonical Twin before broadcasting.")

        # 8. 2D & 3D Synchronization
        print("\n[8/9] Auditing 2D/3D View Synchronization under Live Simulation...")
        twin_st = attack_path_graph.get_node("WEB-01").securityState
        mesh_3d = device_3d_renderer_engine.device_mesh_registry["WEB-01"]

        print(f"    Canonical State : {twin_st}")
        print(f"    3D Emissive Hex : {mesh_3d.emissiveColorHex}")
        assert twin_st == "COMPROMISED"
        assert mesh_3d.emissiveColorHex == "#EF4444"
        print("    [PASS] 2D and 3D states update synchronously.")

        # 9. Monotonic Sequence Ordering Verification
        print("\n[9/9] Auditing Monotonic Sequence Continuity across All Emitted Frames...")
        all_sequences = [m["envelope"]["sequenceNumber"] for m in client_ws.received if m.get("type") == "EVENT"]
        print(f"    Emitted Sequence Numbers Sample: {all_sequences[:8]} ... (Total: {len(all_sequences)})")

        for i in range(len(all_sequences) - 1):
            assert all_sequences[i + 1] > all_sequences[i]
        print("    [PASS] Strictly monotonic sequence ordering confirmed.")

        # Clean reset
        await simulation_realtime_pipeline.reset_simulation()
        websocket_connection_manager.disconnect(client_ws)

    loop.run_until_complete(test_body())
    loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 164 SIMULATION PIPELINE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day164_suite()