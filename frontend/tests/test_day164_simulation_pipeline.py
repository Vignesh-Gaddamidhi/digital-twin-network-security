import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.simulations.simulation_models import ScenarioIdentifierEnum
from frontend.realtime.realtime_models import RealtimeEventType
from frontend.realtime.simulation_realtime_pipeline import simulation_realtime_pipeline
from frontend.realtime.websocket_gateway import websocket_connection_manager

class MockSocket:
    def __init__(self):
        self.messages = []
    async def accept(self):
        pass
    async def send_json(self, data):
        self.messages.append(data)
    async def close(self):
        pass

def run_day164_suite():
    print("=" * 80)
    print("       WEEK 24 - DAY 164: SIMULATION REAL-TIME PIPELINE AUDIT")
    print("=" * 80 + "\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def test_body():
        mock_ws = MockSocket()
        await websocket_connection_manager.connect(mock_ws)

        # 1. Simulation START
        print("[1/9] Auditing Simulation START & Status Broadcast...")
        status_start = await simulation_realtime_pipeline.start_simulation(
            scenario=ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE,
            duration=120
        )
        last_msg = mock_ws.messages[-1]
        exec_state = status_start["status"]["executionState"]
        scenario_val = status_start["status"]["scenario"]
        print(f"    Execution State: {exec_state} | Scenario: {scenario_val}")
        assert exec_state == "RUNNING"
        assert last_msg["envelope"]["eventType"] == RealtimeEventType.SIMULATION_STATUS_UPDATE.value
        print("    [PASS] Simulation START broadcasts SIMULATION_STATUS_UPDATE.")

        # 2. Simulation PAUSE & RESUME
        print("\n[2/9] Auditing Simulation PAUSE & RESUME Controls...")
        res_pause = await simulation_realtime_pipeline.pause_simulation()
        assert res_pause["status"]["executionState"] == "PAUSED"
        print("    PAUSE action verified.")

        res_resume = await simulation_realtime_pipeline.resume_simulation()
        assert res_resume["status"]["executionState"] == "RUNNING"
        print("    RESUME action verified.")
        print("    [PASS] Simulation lifecycle pause and resume controls verified.")

        # 3. Simulation STOP & RESET
        print("\n[3/9] Auditing Simulation STOP & RESET Controls...")
        res_stop = await simulation_realtime_pipeline.stop_simulation()
        assert res_stop["status"]["executionState"] == "STOPPED"
        print("    STOP action verified.")

        res_reset = await simulation_realtime_pipeline.reset_simulation()
        assert res_reset["status"]["executionState"] == "IDLE"
        assert len(attack_path_graph.nodes) >= 5
        print("    RESET action restored clean baseline.")
        print("    [PASS] Simulation lifecycle stop and reset controls verified.")

        # 4. Normal Telemetry Flow Emission
        print("\n[4/9] Auditing Normal Telemetry Flow Emission (TCP/HTTPS)...")
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.NORMAL)
        envelopes_normal = await simulation_realtime_pipeline.process_simulation_tick(step_seconds=5)

        event_types = [e.eventType.value for e in envelopes_normal]
        print(f"    Emitted Event Types: {event_types}")
        assert RealtimeEventType.TRAFFIC_UPDATE.value in event_types
        traffic_env = next(e for e in envelopes_normal if e.eventType == RealtimeEventType.TRAFFIC_UPDATE)
        print(f"    Traffic Flow: {traffic_env.payload['sourceDeviceId']} -> {traffic_env.payload['destinationDeviceId']} ({traffic_env.payload['packetsPerSecond']} pkt/s)")
        assert traffic_env.payload["packetsPerSecond"] > 0
        print("    [PASS] Normal traffic events stream over WebSocket.")

        # 5. Volumetric TRAFFIC_SPIKE Scenario
        print("\n[5/9] Auditing Volumetric TRAFFIC_SPIKE Scenario...")
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.TRAFFIC_SPIKE)
        envelopes_spike = await simulation_realtime_pipeline.process_simulation_tick(step_seconds=20)
        spike_traffic = next(e for e in envelopes_spike if e.eventType == RealtimeEventType.TRAFFIC_UPDATE)

        print(f"    Spike Packet Rate : {spike_traffic.payload['packetsPerSecond']} pkt/s")
        print(f"    Active Connections: {spike_traffic.payload['activeConnections']}")
        assert spike_traffic.payload["packetsPerSecond"] > 500.0
        print("    [PASS] Volumetric traffic surge correctly reflected in stream.")

        # 6. Reconnaissance PORT_ANOMALY Scenario
        print("\n[6/9] Auditing Reconnaissance PORT_ANOMALY Scenario...")
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.PORT_ANOMALY)
        envelopes_port = await simulation_realtime_pipeline.process_simulation_tick(step_seconds=15)
        assert len(envelopes_port) >= 2
        print(f"    Emitted {len(envelopes_port)} events during port anomaly tick.")
        print("    [PASS] PORT_ANOMALY scenario executed and broadcast.")

        # 7. Canonical Twin Mutation Enforcement (Never Bypass Twin)
        print("\n[7/9] Auditing Canonical Twin Mutation (Non-Bypass Invariant)...")
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE)
        envelopes_impact = await simulation_realtime_pipeline.process_simulation_tick(step_seconds=75)

        web_node = attack_path_graph.get_node("WEB-01")
        print(f"    Canonical Twin WEB-01 State: {web_node.securityState}")
        assert web_node.securityState == "COMPROMISED"
        print("    [PASS] Simulation directly mutates Canonical Twin before broadcasting.")

        # 8. 2D/3D View Synchronization under Live Simulation
        print("\n[8/9] Auditing 2D/3D View Synchronization under Live Simulation...")
        vis_3d = device_3d_renderer_engine.device_mesh_registry["WEB-01"]
        print(f"    Canonical State : {web_node.securityState}")
        print(f"    3D Emissive Hex : {vis_3d.emissiveColorHex}")
        assert vis_3d.emissiveColorHex == "#EF4444"
        print("    [PASS] 2D and 3D states update synchronously.")

        # 9. Monotonic Sequence Ordering Continuity
        print("\n[9/9] Auditing Monotonic Sequence Continuity across All Emitted Frames...")
        all_seqs = [msg["envelope"]["sequenceNumber"] for msg in mock_ws.messages if msg.get("type") == "EVENT"]
        print(f"    Emitted Sequence Numbers Sample: {all_seqs[:8]} ... (Total: {len(all_seqs)})")
        for i in range(len(all_seqs) - 1):
            assert all_seqs[i + 1] == all_seqs[i] + 1
        print("    [PASS] Strictly monotonic sequence ordering confirmed.")

        # Clean teardown
        await simulation_realtime_pipeline.reset_simulation()
        await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 164 SIMULATION PIPELINE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day164_suite()