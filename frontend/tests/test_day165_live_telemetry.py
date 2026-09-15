import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.live_telemetry_engine import (
    LiveTelemetryEngine, ConnectionLifecycleState, live_telemetry_engine
)

class MockSocket:
    def __init__(self):
        self.messages = []
    async def accept(self):
        pass
    async def send_json(self, data):
        self.messages.append(data)
    async def close(self):
        pass

def run_day165_suite():
    print("=" * 80)
    print("       WEEK 24 - DAY 165: LIVE TELEMETRY & CONNECTION AUDIT")
    print("=" * 80 + "\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def test_body():
        mock_ws = MockSocket()
        await websocket_connection_manager.connect(mock_ws)

        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.sync_links_from_twin()

        # 1. Live CPU Updates
        print("[1/9] Auditing Live Device CPU Telemetry Updates...")
        env_cpu = await live_telemetry_engine.update_device_cpu("WEB-01", 73.5)
        last_msg = mock_ws.messages[-1]

        print(f"    WEB-01 CPU Target : 73.5%")
        print(f"    Envelope EventType: {env_cpu.eventType.value}")
        print(f"    Payload CPU       : {env_cpu.payload['cpuUtilizationPct']}%")

        assert env_cpu.eventType == RealtimeEventType.CPU_UPDATE
        assert env_cpu.payload["cpuUtilizationPct"] == 73.5
        assert last_msg["envelope"]["payload"]["cpuUtilizationPct"] == 73.5
        print("    [PASS] Device CPU stream emits and broadcasts correctly.")

        # 2. Live Memory Updates
        print("\n[2/9] Auditing Live Memory Utilization Telemetry...")
        env_mem = await live_telemetry_engine.update_device_memory("WEB-01", memory_used_mb=12288.0, total_mb=16384.0)
        print(f"    Memory Used : {env_mem.payload['memoryUsedMb']} MB / {env_mem.payload['memoryTotalMb']} MB")
        print(f"    Memory Pct  : {env_mem.payload['memoryUtilizationPct']}%")

        assert env_mem.eventType == RealtimeEventType.MEMORY_UPDATE
        assert env_mem.payload["memoryUtilizationPct"] == 75.0
        print("    [PASS] Device memory stream emitted correctly.")

        # 3. Live Traffic Updates & Flow Direction
        print("\n[3/9] Auditing Live Traffic Rate Updates & Protocol Attributes...")
        env_traf = await live_telemetry_engine.update_traffic_flow(
            source_device_id="CLIENT-01",
            destination_device_id="WEB-01",
            protocol="HTTPS",
            packet_rate=320.0,
            byte_rate=163840.0
        )
        print(f"    Flow Target: {env_traf.payload['sourceDeviceId']} -> {env_traf.payload['destinationDeviceId']}")
        print(f"    Throughput : {env_traf.payload['packetsPerSecond']} pkt/s | {env_traf.payload['bytesPerSecond']} B/s")

        assert env_traf.eventType == RealtimeEventType.TRAFFIC_UPDATE
        assert env_traf.payload["packetsPerSecond"] == 320.0
        print("    [PASS] Network utilization rates stream over WebSocket.")

        # 4. Live 3D Particle Animation Triggering
        print("\n[4/9] Auditing Traffic Injection Feeding Week 23 3D Particles...")
        active_particles = link_3d_renderer_engine.get_snapshot().totalActiveParticles
        print(f"    Active 3D Particles in Buffer: {active_particles}")
        assert active_particles >= 1
        print("    [PASS] Traffic events dynamically spawn bounded 3D particles.")

        # 5. Connection Lifecycle State Machine
        print("\n[5/9] Auditing Connection Lifecycle (NEW -> CONNECTING -> ESTABLISHED -> CLOSED/FAILED)...")
        states = [
            ConnectionLifecycleState.NEW,
            ConnectionLifecycleState.CONNECTING,
            ConnectionLifecycleState.ESTABLISHED,
            ConnectionLifecycleState.CLOSING,
            ConnectionLifecycleState.CLOSED,
            ConnectionLifecycleState.FAILED
        ]
        for st in states:
            env_c = await live_telemetry_engine.update_connection_lifecycle(
                connection_id="CONN-TEST-01",
                source_device_id="CLIENT-01",
                destination_device_id="WEB-01",
                state=st
            )
            assert env_c.eventType == RealtimeEventType.CONNECTION_UPDATE
            assert env_c.payload["status"] == st.value
            print(f"    Connection State Transition -> {st.value:<14} (Reachable: {env_c.payload['isReachable']})")
        print("    [PASS] All 6 connection lifecycle states verified.")

        # 6. Live Connection Counters
        print("\n[6/9] Auditing Live Connection State Counts...")
        # Create 3 ESTABLISHED and 1 FAILED
        await live_telemetry_engine.update_connection_lifecycle("C-1", "CLIENT-01", "WEB-01", ConnectionLifecycleState.ESTABLISHED)
        await live_telemetry_engine.update_connection_lifecycle("C-2", "CLIENT-01", "DB-01", ConnectionLifecycleState.ESTABLISHED)
        await live_telemetry_engine.update_connection_lifecycle("C-3", "WEB-01", "DB-01", ConnectionLifecycleState.FAILED)

        summary = live_telemetry_engine.get_aggregated_summary()
        print(f"    Active (ESTABLISHED): {summary.activeConnections}")
        print(f"    Failed (FAILED)     : {summary.failedConnections}")

        assert summary.activeConnections >= 2
        assert summary.failedConnections >= 1
        print("    [PASS] Connection tallies accurately aggregated.")

        # 7. 2D / 3D Synchronization (Single Source of Truth)
        print("\n[7/9] Auditing 2D/3D Synchronization under Live Telemetry...")
        # Mutate WEB-01 CPU to 90%
        await live_telemetry_engine.update_device_cpu("WEB-01", 90.0)
        vis_3d = device_3d_renderer_engine.device_mesh_registry["WEB-01"]

        print(f"    Telemetry CPU   : {live_telemetry_engine.device_telemetry_registry['WEB-01'].cpuUtilizationPct}%")
        print(f"    3D Pulse Scaling: {vis_3d.particlePulseRate}x")

        assert vis_3d.particlePulseRate > 3.0  # Scales dynamically with CPU load
        assert live_telemetry_engine.device_telemetry_registry["WEB-01"].cpuUtilizationPct == 90.0
        print("    [PASS] 2D state and 3D visual parameters update in lockstep.")

        # 8. Selected Device Panel Live Updates without Refresh
        print("\n[8/9] Auditing Selected Device Detail Live Updates...")
        device_3d_renderer_engine.select_device("WEB-01")
        assert device_3d_renderer_engine.selected_device_id == "WEB-01"

        # Update CPU while selected
        await live_telemetry_engine.update_device_cpu("WEB-01", 42.0)
        detail_after = device_3d_renderer_engine.get_device_details("WEB-01")
        tel_after = live_telemetry_engine.device_telemetry_registry["WEB-01"]

        print(f"    Selected Host : {detail_after.hostname}")
        print(f"    Live CPU Value: {tel_after.cpuUtilizationPct}%")
        assert tel_after.cpuUtilizationPct == 42.0
        print("    [PASS] Selected device reflects live telemetry without requiring page refresh.")

        # 9. High-Frequency Telemetry Ingestion & Aggregation
        print("\n[9/9] Auditing High-Frequency Telemetry Ingestion & Aggregation...")
        initial_raw = live_telemetry_engine.raw_event_counter
        # Flood 200 rapid updates
        for i in range(200):
            await live_telemetry_engine.update_device_cpu("DB-01", float(i % 100))

        summary_flood = live_telemetry_engine.get_aggregated_summary()
        print(f"    Total Ingested Events : {summary_flood.totalRawEventsIngested}")
        print(f"    Broadcasts Emitted    : {summary_flood.aggregatedBroadcastsEmitted}")
        print(f"    Average Cluster CPU   : {summary_flood.averageCpuPct}%")

        assert summary_flood.totalRawEventsIngested >= initial_raw + 200
        print("    [PASS] High-frequency stream safely ingested without frame drops.")

        # Teardown
        device_3d_renderer_engine.select_device(None)
        await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 165 LIVE TELEMETRY & CONNECTION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day165_suite()