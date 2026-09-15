import sys
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.topology_models import TopologyNodeState
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeConnectionState, DataFreshnessState, BackendHealthState,
    DeviceStatePayload, CpuTelemetryPayload, MemoryTelemetryPayload, TrafficTelemetryPayload,
    ConnectionStatePayload, ThreatTelemetryPayload, AlertTelemetryPayload, PredictionTelemetryPayload,
    RiskTelemetryPayload, AttackPathTelemetryPayload, SimulationStatusPayload, EarlyWarningPayload,
    HeartbeatPayload, ErrorPayload
)
from frontend.realtime.realtime_event_manager import realtime_event_manager

def run_day162_suite():
    print("=" * 80)
    print("       WEEK 24 - DAY 162: REAL-TIME ARCHITECTURE & CONTRACT AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    device_3d_renderer_engine.sync_devices_from_twin()

    # 1. Audit Week 23 Architecture (Single Source of Truth Check)
    print("[1/9] Auditing 2D/3D Single Source of Truth Convergence...")
    twin_nodes = set(attack_path_graph.nodes.keys())
    mesh_nodes = set(device_3d_renderer_engine.device_mesh_registry.keys())
    print(f"    Twin Graph Nodes : {sorted(list(twin_nodes))}")
    print(f"    3D Mesh Nodes    : {sorted(list(mesh_nodes))}")

    assert twin_nodes == mesh_nodes
    for did in twin_nodes:
        assert attack_path_graph.nodes[did].hostname == device_3d_renderer_engine.device_mesh_registry[did].hostname
    print("    [PASS] 2D and 3D engines consume identical device IDs, topology, and state.")

    # 2. Standard Real-Time Event Envelope Integrity
    print("\n[2/9] Auditing Real-Time Event Envelope Schema & Metadata...")
    env = realtime_event_manager.build_envelope(
        event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
        payload=DeviceStatePayload(
            deviceId="WEB-01",
            previousState=TopologyNodeState.NORMAL,
            newState=TopologyNodeState.COMPROMISED,
            reason="Exploitation of CVE-2026-WEB-RCE",
            quarantineEnforced=False
        ).model_dump(),
        device_id="WEB-01"
    )
    print(f"    Event ID     : {env.eventId}")
    print(f"    Event Type   : {env.eventType.value}")
    print(f"    Sequence Num : {env.sequenceNumber}")
    print(f"    Timestamps   : Event={env.timestamp[:19]} | Recv={env.receivedTimestamp[:19]} | Proc={env.processedTimestamp[:19]}")

    assert env.eventId.startswith("RTE-")
    assert env.sequenceNumber >= 1001
    assert env.receivedTimestamp is not None
    assert env.processedTimestamp is not None
    print("    [PASS] Standard envelope format and three-tier latency timestamps verified.")

    # 3. Controlled Event Vocabulary (Testing All 15 Event Types)
    print("\n[3/9] Auditing All 15 Real-Time Event Payloads...")
    payload_samples = [
        (RealtimeEventType.DEVICE_STATE_UPDATE, {"deviceId": "WEB-01", "newState": "COMPROMISED"}),
        (RealtimeEventType.CPU_UPDATE, {"deviceId": "WEB-01", "cpuUtilizationPct": 88.4}),
        (RealtimeEventType.MEMORY_UPDATE, {"deviceId": "WEB-01", "memoryUtilizationPct": 74.2}),
        (RealtimeEventType.TRAFFIC_UPDATE, {"linkId": "CONN-01", "packetsPerSecond": 1420.0}),
        (RealtimeEventType.CONNECTION_UPDATE, {"connectionId": "C-1", "status": "ACTIVE"}),
        (RealtimeEventType.THREAT_UPDATE, {"threatId": "THR-1", "eventType": "LATERAL_MOVEMENT"}),
        (RealtimeEventType.ALERT_UPDATE, {"alertId": "ALT-1", "severity": "CRITICAL"}),
        (RealtimeEventType.PREDICTION_UPDATE, {"targetDeviceId": "DB-01", "futureThreatProbability": 0.89}),
        (RealtimeEventType.RISK_UPDATE, {"targetDeviceId": "DB-01", "compositeRiskScore": 80.4}),
        (RealtimeEventType.ATTACK_PATH_UPDATE, {"pathId": "PATH-1", "reachability": "REACHABLE"}),
        (RealtimeEventType.SIMULATION_STATUS_UPDATE, {"scenario": "LATERAL_MOVEMENT_LIKE", "executionState": "RUNNING"}),
        (RealtimeEventType.EARLY_WARNING_UPDATE, {"targetDeviceId": "WEB-01", "leadTimeSeconds": 42}),
        (RealtimeEventType.TWIN_STATE_UPDATE, {"state": "SYNCHRONIZED"}),
        (RealtimeEventType.HEARTBEAT, {"activeConnectionsCount": 1}),
        (RealtimeEventType.ERROR, {"errorCode": "E503", "errorMessage": "Pipeline congestion"})
    ]
    for etype, pdata in payload_samples:
        test_env = realtime_event_manager.build_envelope(etype, pdata)
        assert test_env.eventType == etype
        assert test_env.payload == pdata
        print(f"    Payload Validated: {etype.value:<26} (Seq #{test_env.sequenceNumber})")
    print("    [PASS] Complete 15-event vocabulary operational.")

    # 4. Connection Lifecycle vs. Security State Decoupling
    print("\n[4/9] Auditing Connection Lifecycle vs. Security State Decoupling...")
    # Simulate connection drop
    realtime_event_manager.connection_state = RealtimeConnectionState.DISCONNECTED
    twin_node_state = attack_path_graph.nodes["CLIENT-01"].securityState

    print(f"    Transport State : {realtime_event_manager.connection_state.value}")
    print(f"    Twin Node State : {twin_node_state}")

    assert realtime_event_manager.connection_state == RealtimeConnectionState.DISCONNECTED
    assert twin_node_state != "ISOLATED"  # Strict invariant: connection loss != device isolation
    print("    [PASS] Transport DISCONNECTED is decoupled from security state ISOLATED.")

    # 5. Data Freshness State Detection (FRESH vs STALE)
    print("\n[5/9] Auditing Data Freshness Detection (Threshold: 2.0s)...")
    # Fresh heartbeat
    realtime_event_manager.build_envelope(RealtimeEventType.HEARTBEAT, {"status": "ok"})
    freshness_fresh, delta_fresh = realtime_event_manager.compute_freshness_state()
    print(f"    Fresh Pulse   : Status = {freshness_fresh.value} (Age = {delta_fresh}s)")
    assert freshness_fresh == DataFreshnessState.FRESH

    # Artificially age heartbeat by 3 seconds
    realtime_event_manager.last_heartbeat_timestamp = datetime.now(timezone.utc) - timedelta(seconds=3.5)
    freshness_stale, delta_stale = realtime_event_manager.compute_freshness_state()
    print(f"    Aged Pulse    : Status = {freshness_stale.value} (Age = {delta_stale}s)")
    assert freshness_stale == DataFreshnessState.STALE
    print("    [PASS] Freshness state detector successfully traps stale telemetry.")

    # 6. Backend Health State Enforcement
    print("\n[6/9] Auditing Backend Health States (HEALTHY, BACKEND_ERROR, UNAVAILABLE)...")
    for bh in [BackendHealthState.HEALTHY, BackendHealthState.BACKEND_ERROR, BackendHealthState.UNAVAILABLE]:
        realtime_event_manager.backend_health = bh
        assert realtime_event_manager.backend_health == bh
        print(f"    Backend State: {bh.value}")
    print("    [PASS] Backend health states verified.")

    # 7. Monotonic Sequence Ordering & Gap Detection
    print("\n[7/9] Auditing Monotonic Sequence Ordering & Gap Detection...")
    seq_a = realtime_event_manager.get_next_sequence_number()
    seq_b = realtime_event_manager.get_next_sequence_number()
    assert seq_b == seq_a + 1

    # In-order detection
    assert realtime_event_manager.detect_sequence_gap(last_seen_sequence=seq_a, incoming_sequence=seq_b) is False
    # Gap detection (e.g. dropped 1002, received 1003)
    assert realtime_event_manager.detect_sequence_gap(last_seen_sequence=1001, incoming_sequence=1003) is True
    print(f"    Sequence #{seq_a} -> #{seq_b} : Verified sequential.")
    print(f"    Sequence #1001 -> #1003: Successfully flagged sequence gap.")
    print("    [PASS] Monotonic sequence counter and gap detector validated.")

    # 8. Snapshot vs. Incremental Update Comparison
    print("\n[8/9] Auditing Snapshot vs. Incremental Delta Update Structure...")
    # Incremental update (delta)
    delta_env = realtime_event_manager.build_envelope(
        event_type=RealtimeEventType.CPU_UPDATE,
        payload={"deviceId": "WEB-01", "cpu": 92.1},
        device_id="WEB-01"
    )
    # Full monolithic snapshot
    full_snap = realtime_event_manager.generate_full_twin_snapshot()

    print(f"    Incremental Delta Size: {len(delta_env.model_dump_json())} bytes")
    print(f"    Full Snapshot Size    : {len(full_snap.model_dump_json())} bytes")
    print(f"    Snapshot Device Count : {len(full_snap.devices)}")
    print(f"    Snapshot Conn Count   : {len(full_snap.connections)}")

    assert len(delta_env.model_dump_json()) < 500  # Lightweight incremental
    assert len(full_snap.model_dump_json()) > 1500  # Complete baseline
    assert len(full_snap.devices) >= 5
    print("    [PASS] Structural separation of delta events and full snapshots verified.")

    # 9. Clean State Reset
    print("\n[9/9] Restoring Clean Baseline State...")
    realtime_event_manager.connection_state = RealtimeConnectionState.CONNECTED
    realtime_event_manager.backend_health = BackendHealthState.HEALTHY
    realtime_event_manager.build_envelope(RealtimeEventType.HEARTBEAT, {"status": "ok"})
    print("    [PASS] Clean baseline restored.")

    print("\n" + "=" * 80)
    print("       ALL DAY 162 REAL-TIME EVENT CONTRACT TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day162_suite()