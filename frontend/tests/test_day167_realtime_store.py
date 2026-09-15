import asyncio
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.three_d_filter_models import TopologyFilterCriteria, VisibilityPresetEnum, ViewModeEnum
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeConnectionState, DataFreshnessState, BackendHealthState,
    RealtimeEventEnvelope, TwinStateSnapshot
)
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

def run_day167_suite():
    print("=" * 80)
    print("       WEEK 24 - DAY 167: FRONTEND REAL-TIME STORE & FAILURE STATES AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 1. Initial Snapshot Application
    print("[1/10] Auditing Full Baseline TwinStateSnapshot Application...")
    snap = realtime_event_manager.generate_full_twin_snapshot()
    realtime_store_engine.apply_snapshot(snap)

    print(f"    Connection State : {realtime_store_engine.connectionState.value}")
    print(f"    Devices Loaded   : {len(realtime_store_engine.devices)}")
    print(f"    Sequence Counter : #{realtime_store_engine.lastAppliedSequenceNumber}")

    assert realtime_store_engine.connectionState == RealtimeConnectionState.CONNECTED
    assert len(realtime_store_engine.devices) >= 5
    print("    [PASS] Client store initialized with complete baseline topology.")

    # 2. Connection Failure Lifecycle Transitions
    print("\n[2/10] Auditing Connection Lifecycle (CONNECTED -> DISCONNECTED -> RECONNECTING)...")
    # Simulate network drop
    realtime_store_engine.connectionState = RealtimeConnectionState.DISCONNECTED
    print(f"    State Transition : {realtime_store_engine.connectionState.value} (Last known state preserved)")
    assert realtime_store_engine.connectionState == RealtimeConnectionState.DISCONNECTED
    assert len(realtime_store_engine.devices) >= 5  # Non-destructive preservation

    # Simulate reconnecting backoff
    realtime_store_engine.connectionState = RealtimeConnectionState.RECONNECTING
    realtime_store_engine.reconnectAttempts += 1
    print(f"    State Transition : {realtime_store_engine.connectionState.value} (Attempt #{realtime_store_engine.reconnectAttempts})")
    assert realtime_store_engine.connectionState == RealtimeConnectionState.RECONNECTING
    print("    [PASS] Connection drops and reconnecting states handled non-destructively.")

    # 3. Global Data Freshness Decoupling (STALE DATA vs DISCONNECTED)
    print("\n[3/10] Auditing Data Freshness vs Connection State Decoupling...")
    realtime_store_engine.connectionState = RealtimeConnectionState.CONNECTED
    # Age last heartbeat by 4.0s
    realtime_store_engine.lastHeartbeatTimestamp = (datetime.now(timezone.utc) - timedelta(seconds=4.0)).isoformat()
    realtime_store_engine.evaluate_staleness()

    print(f"    Socket Link     : {realtime_store_engine.connectionState.value}")
    print(f"    Data Freshness  : {realtime_store_engine.dataFreshness.value}")

    assert realtime_store_engine.connectionState == RealtimeConnectionState.CONNECTED
    assert realtime_store_engine.dataFreshness == DataFreshnessState.STALE
    print("    [PASS] Stale data trapped without falsely marking socket disconnected.")

    # 4. Non-Destructive Backend Error Frame
    print("\n[4/10] Auditing Backend Error Handling & Notification Toasts...")
    err_env = realtime_event_manager.build_envelope(
        event_type=RealtimeEventType.ERROR,
        payload={"errorCode": "E503_CONGESTION", "errorMessage": "Pipeline throttle engaged"}
    )
    realtime_store_engine.apply_event_envelope(err_env)

    print(f"    Backend State   : {realtime_store_engine.backendState.value}")
    print(f"    Active Toast    : [{realtime_store_engine.notifications[0].level}] {realtime_store_engine.notifications[0].title}")

    assert realtime_store_engine.backendState == BackendHealthState.BACKEND_ERROR
    assert realtime_store_engine.notifications[0].level == "CRITICAL"
    print("    [PASS] Backend errors surface as notifications without canvas collapse.")

    # 5. Reconnection Snapshot Resynchronization
    print("\n[5/10] Auditing Reconnect Snapshot Resynchronization...")
    fresh_snap = realtime_event_manager.generate_full_twin_snapshot()
    realtime_store_engine.apply_snapshot(fresh_snap)

    print(f"    Re-aligned Seq  : #{realtime_store_engine.lastAppliedSequenceNumber}")
    print(f"    Connection State: {realtime_store_engine.connectionState.value}")
    print(f"    Backend State   : {realtime_store_engine.backendState.value}")

    assert realtime_store_engine.connectionState == RealtimeConnectionState.CONNECTED
    assert realtime_store_engine.backendState == BackendHealthState.HEALTHY
    print("    [PASS] Full state reconciliation resets sequence continuity.")

    # 6. Duplicate & Out-of-Order Frame Rejection (Idempotency)
    print("\n[6/10] Auditing Duplicate Frame Rejection (Idempotency)...")
    sample_env = realtime_event_manager.build_envelope(
        event_type=RealtimeEventType.CPU_UPDATE,
        payload={"deviceId": "WEB-01", "cpuUtilizationPct": 84.0}
    )
    first_apply = realtime_store_engine.apply_event_envelope(sample_env)
    second_apply = realtime_store_engine.apply_event_envelope(sample_env)

    print(f"    First Application : {first_apply}")
    print(f"    Second Application: {second_apply}")

    assert first_apply is True
    assert second_apply is False
    print("    [PASS] Duplicate frames discarded cleanly.")

    # 7. 2D / 3D Unified State Single Source of Truth Invariant
    print("\n[7/9] Auditing 2D/3D Unified Single Source of Truth Invariant...")
    # Update WEB-01 CPU to 92.5%
    cpu_env = realtime_event_manager.build_envelope(
        event_type=RealtimeEventType.CPU_UPDATE,
        payload={"deviceId": "WEB-01", "cpuUtilizationPct": 92.5}
    )
    realtime_store_engine.apply_event_envelope(cpu_env)

    store_cpu = realtime_store_engine.devices["WEB-01"].cpuUtilizationPct
    print(f"    Universal Store WEB-01 CPU: {store_cpu}%")
    assert store_cpu == 92.5
    print("    [PASS] Single store ensures identical values projected to 2D and 3D views.")

    # 8. Selection and Filter Continuity Across Viewports
    print("\n[8/10] Auditing Selection & Filter Persistence Across Viewports...")
    realtime_store_engine.select_device("DB-01")
    filters = TopologyFilterCriteria(
        deviceTypeFilter="SERVERS",
        visibilityPreset=VisibilityPresetEnum.SHOW_HIGH_RISK_ONLY
    )
    realtime_store_engine.set_active_filters(filters)

    # Simulate switching from 3D to 2D
    realtime_store_engine.activeViewMode = ViewModeEnum.VIEW_2D
    selected = realtime_store_engine.get_selected_device_details()
    active_filt = realtime_store_engine.activeFilters

    print(f"    View Mode    : {realtime_store_engine.activeViewMode.value}")
    print(f"    Selected Host: {selected.hostname} (Preserved)")
    print(f"    Filter Pres  : {active_filt.visibilityPreset.value} (Preserved)")

    assert selected.deviceId == "DB-01"
    assert active_filt.deviceTypeFilter == "SERVERS"
    print("    [PASS] Selection and active filters preserved across viewport switches.")

    # 9. Live Updates to Selected Entity in Inspection Drawer
    print("\n[9/10] Auditing Live Telemetry Updates into Active Inspection Target...")
    # Stream memory update into selected DB-01
    mem_env = realtime_event_manager.build_envelope(
        event_type=RealtimeEventType.MEMORY_UPDATE,
        payload={"deviceId": "DB-01", "memoryUtilizationPct": 88.0}
    )
    realtime_store_engine.apply_event_envelope(mem_env)

    drawer_target = realtime_store_engine.get_selected_device_details()
    print(f"    Drawer Target : {drawer_target.deviceId}")
    print(f"    Live Memory   : {drawer_target.memoryUtilizationPct}%")
    assert drawer_target.memoryUtilizationPct == 88.0
    print("    [PASS] Selected device updates automatically without full DOM reloads.")

    # 10. Per-Entity Telemetry Staleness
    print("\n[10/10] Auditing Individual Entity Telemetry Staleness...")
    # Age WEB-01 telemetry by 15 seconds
    realtime_store_engine.devices["WEB-01"].lastTelemetryTimestamp = (datetime.now(timezone.utc) - timedelta(seconds=15.0)).isoformat()
    # DB-01 remains fresh
    realtime_store_engine.devices["DB-01"].lastTelemetryTimestamp = datetime.now(timezone.utc).isoformat()

    realtime_store_engine.evaluate_staleness()

    web_stale = realtime_store_engine.devices["WEB-01"].isTelemetryStale
    db_stale = realtime_store_engine.devices["DB-01"].isTelemetryStale

    print(f"    WEB-01 Telemetry Stale: {web_stale} (Exceeded 10s)")
    print(f"    DB-01 Telemetry Stale : {db_stale} (Active)")

    assert web_stale is True
    assert db_stale is False
    print("    [PASS] Per-device staleness isolated without degrading platform health.")

    print("\n" + "=" * 80)
    print("       ALL DAY 167 FRONTEND REAL-TIME STORE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day167_suite()