import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.twin_core import DigitalTwinCore
from services.digital_twin.telemetry.sync_engine import TwinSynchronizationEngine
from services.twin_engine.src.core.twin_state import DeviceEntity, DeviceInterface
from packages.shared_types.src.telemetry import TelemetryMetricEvent
from packages.shared_types.src.events import SecurityEvent
from pydantic import ValidationError

def run_failure_resiliency_suite():
    print("================================================================================")
    print("       WEEK 4 - DAY 28: BOUNDARY FAILURE & RESILIENCY TEST SUITE                ")
    print("================================================================================\n")

    twin = DigitalTwinCore(network_name="FAIL-TEST-NET")
    sync = TwinSynchronizationEngine(twin)

    # 1. Unknown Device Telemetry Rejection
    print("[1/6] Testing Telemetry Ingest on Unknown Device...")
    try:
        sync.ingest_metric_telemetry(TelemetryMetricEvent(device_id="DEV-NONEXISTENT", metric="packet_rate", value=100.0))
        assert False, "Failed to reject unknown device ID!"
    except KeyError as e:
        print(f"    [PASS] Safely rejected unknown device: {e}")

    # 2. Duplicate Device Creation Rejection
    print("\n[2/6] Testing Duplicate Device ID Registration...")
    d1 = DeviceEntity(id="DEV-001", hostname="node1", type="SERVER", interfaces=[])
    twin.register_device(d1)
    try:
        twin.register_device(d1)
        assert False, "Failed to reject duplicate device ID!"
    except ValueError as e:
        print(f"    [PASS] Safely blocked duplicate device registration: {e}")

    # 3. Invalid Metric Rejection
    print("\n[3/6] Testing Unsupported Metric Schema Validation...")
    try:
        TelemetryMetricEvent(device_id="DEV-001", metric="INVALID_METRIC_NAME", value=50.0)
        assert False, "Failed to validate metric type!"
    except ValidationError as e:
        print("    [PASS] Pydantic rejected unsupported metric field.")

    # 4. Invalid Timestamp Format Rejection
    print("\n[4/6] Testing Malformed Timestamp Schema...")
    try:
        TelemetryMetricEvent(device_id="DEV-001", metric="packet_rate", value=50.0, timestamp="INVALID_DATE_STRING")
        assert False, "Failed to validate timestamp!"
    except ValidationError as e:
        print("    [PASS] Pydantic rejected malformed timestamp.")

    # 5. Invalid Unresolvable Anomaly Event
    print("\n[5/6] Testing Anomaly Event with Unmapped IP...")
    unmapped_sec = SecurityEvent(
        destination_ip="172.31.255.255",
        source_ip="10.0.0.1",
        protocol="TCP",
        event_type="PORT_SCAN",
        severity="HIGH"
    )
    try:
        sync.ingest_anomaly_security_event(unmapped_sec)
        assert False, "Failed to reject unmapped destination IP!"
    except KeyError as e:
        print(f"    [PASS] Safely rejected unresolvable security event: {e}")

    # 6. Topological Pathfinding Across Disconnected Graphs
    print("\n[6/6] Testing Pathfinding on Disconnected Nodes...")
    d2 = DeviceEntity(id="DEV-002", hostname="isolated-node", type="SERVER", interfaces=[])
    twin.register_device(d2)
    path_res = twin.find_path("DEV-001", "DEV-002")
    assert not path_res.is_connected
    assert path_res.hop_count == 0
    print("    [PASS] Disconnected pathfinding returned is_connected=False without error.")

    print("\n================================================================================")
    print("       ALL 6 RESILIENCY & FAILURE TESTS PASSED CLEANLY                          ")
    print("================================================================================")

if __name__ == "__main__":
    run_failure_resiliency_suite()