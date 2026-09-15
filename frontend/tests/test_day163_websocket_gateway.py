import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeConnectionState, RealtimeEventEnvelope
)
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_client_sync import realtime_client_sync

class MockWebSocket:
    """Mock WebSocket simulating FastAPI Starlette socket for synchronous/asynchronous unit tests."""
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.is_open = False
        self.received_messages = []

    async def accept(self):
        self.is_open = True

    async def send_json(self, data: dict):
        if not self.is_open:
            raise RuntimeError("WebSocket is closed")
        self.received_messages.append(data)

    async def close(self):
        self.is_open = False

def run_day163_suite():
    print("=" * 80)
    print("       WEEK 24 - DAY 163: FASTAPI WEBSOCKET GATEWAY AUDIT")
    print("=" * 80 + "\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def test_body():
        # 1. First Connection & Handshake Snapshot
        print("[1/10] Auditing First Client Connection & Automatic Snapshot Dispatch...")
        ws1 = MockWebSocket("client-2d")
        snap = await websocket_connection_manager.connect(ws1)

        print(f"    Client 1 Connected. Active Count: {websocket_connection_manager.connection_count()}")
        print(f"    Initial Message Type: {ws1.received_messages[0]['type']}")
        print(f"    Snapshot Devices    : {len(snap.devices)}")

        assert websocket_connection_manager.connection_count() == 1
        assert ws1.received_messages[0]["type"] == "SNAPSHOT"
        assert len(snap.devices) >= 5
        print("    [PASS] Initial handshake delivers full baseline snapshot.")

        # 2. Multiple Concurrent Client Registration
        print("\n[2/10] Auditing Multiple Concurrent Client Connections...")
        ws2 = MockWebSocket("client-3d")
        ws3 = MockWebSocket("client-soc")
        await websocket_connection_manager.connect(ws2)
        await websocket_connection_manager.connect(ws3)

        print(f"    Total Active Clients: {websocket_connection_manager.connection_count()}")
        assert websocket_connection_manager.connection_count() == 3
        print("    [PASS] Multiple client multiplexing verified.")

        # 3. Multiplexed Event Broadcasting
        print("\n[3/10] Auditing Broadcast Distribution across All Active Sockets...")
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.CPU_UPDATE,
            payload={"deviceId": "WEB-01", "cpuUtilizationPct": 91.5},
            device_id="WEB-01"
        )
        delivered = await websocket_connection_manager.broadcast_envelope(env)
        print(f"    Delivered to {delivered} clients.")
        assert delivered == 3
        for ws in [ws1, ws2, ws3]:
            last_msg = ws.received_messages[-1]
            assert last_msg["type"] == "EVENT"
            assert last_msg["envelope"]["payload"]["cpuUtilizationPct"] == 91.5
        print("    [PASS] Broadcast successfully dispatched to all active sockets.")

        # 4. Disconnection Handling
        print("\n[4/10] Auditing Client Disconnection Flow...")
        websocket_connection_manager.disconnect(ws2)
        print(f"    Disconnected Client 2. Remaining Active: {websocket_connection_manager.connection_count()}")
        assert websocket_connection_manager.connection_count() == 2
        print("    [PASS] Clean disconnection and count decrement verified.")

        # 5. Heartbeat Pulse Verification
        print("\n[5/10] Auditing Server Heartbeat Pulse Generation...")
        hb_env = await websocket_connection_manager.trigger_heartbeat()
        print(f"    Heartbeat Sequence: #{hb_env.sequenceNumber}")
        print(f"    Active Conns in HB: {hb_env.payload['activeConnectionsCount']}")
        assert hb_env.eventType == RealtimeEventType.HEARTBEAT
        assert hb_env.payload["activeConnectionsCount"] == 2
        print("    [PASS] Periodic heartbeat pulse verified.")

        # 6. Client Sync & Incremental Delta Application
        print("\n[6/10] Auditing Client-Side State Ingestion & Mutation...")
        realtime_client_sync.apply_initial_snapshot(snap)
        assert realtime_client_sync.connection_state == RealtimeConnectionState.CONNECTED

        delta_env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
            payload={"deviceId": "WEB-01", "newState": "COMPROMISED"},
            device_id="WEB-01"
        )
        applied = realtime_client_sync.apply_incremental_envelope(delta_env)
        assert applied is True

        web_dev = next(d for d in realtime_client_sync.client_twin_state["devices"] if d["deviceId"] == "WEB-01")
        assert web_dev["securityState"] == "COMPROMISED"
        print("    Client-side WEB-01 state updated to COMPROMISED.")
        print("    [PASS] Incremental delta application verified.")

        # 7. Duplicate Event Rejection (Idempotency)
        print("\n[7/10] Auditing Duplicate Event Protection (Idempotency Filter)...")
        dup_applied = realtime_client_sync.apply_incremental_envelope(delta_env)
        print(f"    Re-applying Same Envelope: applied={dup_applied} | Rejections={realtime_client_sync.duplicates_rejected}")
        assert dup_applied is False
        assert realtime_client_sync.duplicates_rejected >= 1
        print("    [PASS] Duplicate event dropped without state corruption.")

        # 8. Out-of-Order Frame & Sequence Gap Detection
        print("\n[8/10] Auditing Sequence Gap Detection...")
        curr_seq = realtime_client_sync.last_applied_sequence
        gap_env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.TRAFFIC_UPDATE,
            payload={"linkId": "L-1", "packets": 200}
        )
        gap_env.sequenceNumber = curr_seq + 5

        applied_gap = realtime_client_sync.apply_incremental_envelope(gap_env)
        assert applied_gap is True
        assert realtime_client_sync.sequence_gaps_detected >= 1
        print(f"    Sequence Gap Flagged. Detected Gaps: {realtime_client_sync.sequence_gaps_detected}")
        print("    [PASS] Non-consecutive packet sequences flagged.")

        # 9. Bounded Exponential Backoff on Reconnect
        print("\n[9/10] Auditing Exponential Backoff Delays...")
        realtime_client_sync.connection_state = RealtimeConnectionState.RECONNECTING
        d1 = realtime_client_sync.compute_reconnect_backoff_delay()
        d2 = realtime_client_sync.compute_reconnect_backoff_delay()
        d3 = realtime_client_sync.compute_reconnect_backoff_delay()
        d4 = realtime_client_sync.compute_reconnect_backoff_delay()
        d5 = realtime_client_sync.compute_reconnect_backoff_delay()
        print(f"    Backoff Schedule: {d1}s -> {d2}s -> {d3}s -> {d4}s -> {d5}s (Max: 10.0s)")

        assert d1 == 1.0
        assert d2 == 2.0
        assert d3 == 4.0
        assert d4 == 8.0
        assert d5 == 10.0
        print("    [PASS] Exponential backoff conforms to bounded limits.")

        # 10. Reconnect Resynchronization & Sanitized Backend Error
        print("\n[10/10] Auditing Reconnect Resynchronization & Sanitized Error Frame...")
        fresh_snap = realtime_event_manager.generate_full_twin_snapshot()
        skipped_events = realtime_client_sync.handle_reconnect_resync(fresh_snap)
        print(f"    Resynchronized with Snapshot #{fresh_snap.sequenceNumber} (Skipped {skipped_events} lost frames)")
        assert realtime_client_sync.connection_state == RealtimeConnectionState.CONNECTED
        assert realtime_client_sync.last_applied_sequence == fresh_snap.sequenceNumber

        await websocket_connection_manager.broadcast_error("E500_INFERENCE_TIMEOUT", "ML Inference gateway timeout", "ML_ENGINE")
        err_msg = ws1.received_messages[-1]
        assert err_msg["envelope"]["eventType"] == "ERROR"
        assert err_msg["envelope"]["payload"]["errorCode"] == "E500_INFERENCE_TIMEOUT"
        assert "traceback" not in err_msg["envelope"]["payload"]
        print("    [PASS] Reconnection resynchronization and sanitized error broadcast validated.")

        websocket_connection_manager.disconnect(ws1)
        websocket_connection_manager.disconnect(ws3)

    loop.run_until_complete(test_body())
    loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 163 WEBSOCKET GATEWAY TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day163_suite()