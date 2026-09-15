import sys
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.dashboard.integration_models import ConnectionStateEnum, SubsystemStatusEnum
from frontend.dashboard.dashboard_integration_engine import dashboard_integration_engine

def run_day153_suite():
    print("=" * 80)
    print("       WEEK 22 - DAY 153: DASHBOARD INTEGRATION & REAL-TIME AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    dashboard_integration_engine.pulse_telemetry()
    dashboard_integration_engine.set_connection_state(ConnectionStateEnum.CONNECTED)

    # 1. Subsystem Health Probing
    print("[1/8] Auditing Subsystem Health Probing & Connectivity...")
    h = dashboard_integration_engine.get_subsystem_health()
    print(f"    Backend Connection : {h.backendConnection.value}")
    print(f"    Digital Twin Sync  : {h.digitalTwinSync.value}")
    print(f"    Telemetry Stream   : {h.telemetryStream.value}")
    print(f"    ML Inference       : {h.mlInference.value}")
    print(f"    Data Age           : {h.dataAgeSeconds}s (isStale: {h.isStale})")

    assert h.backendConnection == ConnectionStateEnum.CONNECTED
    assert h.digitalTwinSync == SubsystemStatusEnum.SYNCED
    assert h.telemetryStream == SubsystemStatusEnum.ACTIVE
    assert h.isStale is False
    print("    [PASS] Subsystem health indicators verified.")

    # 2. Connection State Transitions (Loss & Reconnection)
    print("\n[2/8] Auditing Connection Loss & Reconnection Flow...")
    dashboard_integration_engine.set_connection_state(ConnectionStateEnum.DISCONNECTED)
    assert dashboard_integration_engine.get_subsystem_health().backendConnection == ConnectionStateEnum.DISCONNECTED
    print("    Transitioned -> DISCONNECTED verified.")

    dashboard_integration_engine.set_connection_state(ConnectionStateEnum.RECONNECTING)
    assert dashboard_integration_engine.get_subsystem_health().backendConnection == ConnectionStateEnum.RECONNECTING
    print("    Transitioned -> RECONNECTING verified.")

    dashboard_integration_engine.set_connection_state(ConnectionStateEnum.CONNECTED)
    assert dashboard_integration_engine.get_subsystem_health().backendConnection == ConnectionStateEnum.CONNECTED
    print("    Transitioned -> CONNECTED restored.")
    print("    [PASS] Connection state machine verified.")

    # 3. Telemetry Staleness Detection (> 5.0s delay)
    print("\n[3/8] Auditing Telemetry Staleness Detection...")
    # Artificially age heartbeat by 10 seconds
    dashboard_integration_engine.last_telemetry_heartbeat = datetime.now(timezone.utc) - timedelta(seconds=10)
    h_stale = dashboard_integration_engine.get_subsystem_health()
    print(f"    Aged Telemetry: Data Age = {h_stale.dataAgeSeconds}s | Status = {h_stale.telemetryStream.value}")
    assert h_stale.isStale is True
    assert h_stale.telemetryStream == SubsystemStatusEnum.STALE

    # Pulse fresh telemetry
    dashboard_integration_engine.pulse_telemetry()
    h_fresh = dashboard_integration_engine.get_subsystem_health()
    assert h_fresh.isStale is False
    assert h_fresh.telemetryStream == SubsystemStatusEnum.ACTIVE
    print("    [PASS] Telemetry staleness detection and recovery verified.")

    # 4. Pipeline Observability Telemetry
    print("\n[4/8] Auditing Pipeline Latency & Observability Telemetry...")
    obs = dashboard_integration_engine.observability
    print(f"    Events / sec       : {obs.eventsPerSecond} ev/s")
    print(f"    Processing Latency : {obs.processingLatencyMs} ms")
    print(f"    Prediction Latency : {obs.predictionLatencyMs} ms")
    print(f"    API Latency        : {obs.apiLatencyMs} ms")
    print(f"    Dropped Events     : {obs.droppedEventsCount}")

    assert obs.eventsPerSecond > 0.0
    assert obs.processingLatencyMs < 20.0
    assert obs.predictionLatencyMs < 10.0
    print("    [PASS] Pipeline observability latencies validated.")

    # 5. Global Multi-Entity Search (Device & IP query)
    print("\n[5/8] Auditing Unified Global Search (Query: 'DB-01')...")
    res_db = dashboard_integration_engine.global_search("DB-01")
    print(f"    Matches Found: {res_db.totalMatches}")
    for m in res_db.results:
        print(f"      * [{m.category:<10}] {m.title:<30} DeepLink: {m.deepLinkRoute}")

    assert res_db.totalMatches >= 1
    assert any(m.category == "DEVICE" for m in res_db.results)
    assert any(m.category == "ALERT" for m in res_db.results)
    print("    [PASS] Global search across devices and alerts verified.")

    # 6. Global Multi-Entity Search (IP Address query)
    print("\n[6/8] Auditing Unified Global Search by IP Address ('192.168.30.10')...")
    res_ip = dashboard_integration_engine.global_search("192.168.30.10")
    assert res_ip.totalMatches >= 1
    assert res_ip.results[0].identifier == "DB-01"
    print(f"    Resolved IP 192.168.30.10 -> Device: {res_ip.results[0].identifier}")
    print("    [PASS] Search by IP address verified.")

    # 7. Global Time-Range Selector Synchronization
    print("\n[7/8] Auditing Global Time-Range Synchronization...")
    for tr in ["5m", "15m", "30m", "1h", "6h", "24h"]:
        updated_tr = dashboard_integration_engine.set_global_time_range(tr)
        assert updated_tr == tr
        print(f"    Synchronized Global Horizon: [{updated_tr}]")
    print("    [PASS] Global time-range selector synchronized.")

    # 8. Real-Time WebSocket Frame Generation
    print("\n[8/8] Auditing Real-Time WebSocket Frame Assembly...")
    frame = dashboard_integration_engine.generate_realtime_frame()
    print(f"    Frame ID    : {frame.frameId}")
    print(f"    Timestamp   : {frame.timestamp}")
    print(f"    Health      : Backend={frame.health.backendConnection.value}")
    print(f"    Risk Score  : {frame.networkRiskScore:.1f}")
    print(f"    Active Conns: {frame.currentPacketsPerSec} pkts/s")

    assert frame.frameId.startswith("FRM-")
    assert frame.networkRiskScore > 0.0
    print("    [PASS] Real-time dashboard frame validated.")

    print("\n" + "=" * 80)
    print("       ALL DAY 153 DASHBOARD INTEGRATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day153_suite()