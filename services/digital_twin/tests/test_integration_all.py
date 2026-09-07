import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.twin_core import DigitalTwinCore
from services.digital_twin.telemetry.sync_engine import TwinSynchronizationEngine
from services.twin_engine.src.core.twin_state import DeviceEntity, DeviceInterface
from packages.shared_types.src.topology import ConnectionEntity
from packages.shared_types.src.device import PortEntity, ServiceEntity
from packages.shared_types.src.security import VulnerabilityEntity
from packages.shared_types.src.telemetry import TelemetryMetricEvent
from packages.shared_types.src.events import SecurityEvent

def run_10_point_integration():
    print("================================================================================")
    print("       WEEK 4 - DAY 28: DIGITAL TWIN 10-POINT INTEGRATION TEST SUITE            ")
    print("================================================================================\n")

    twin = DigitalTwinCore(network_name="TEST-NET")
    sync = TwinSynchronizationEngine(twin)

    # Test 1: Create device
    print("[1/10] Test 1: Create Device...")
    d1 = DeviceEntity(
        id="DEV-001",
        hostname="ws-pc-01",
        type="WORKSTATION",
        interfaces=[DeviceInterface(interface_id="eth0", ip_address="192.168.1.11", mac_address="00:50:56:FE:01:11", subnet="192.168.1.0/24")],
        criticality=4.0
    )
    twin.register_device(d1)
    assert twin.devices.get_device("DEV-001") is not None
    print("    [PASS] Device created successfully.")

    # Test 2: Update IP
    print("\n[2/10] Test 2: Update IP Address...")
    d1.interfaces[0].ip_address = "192.168.1.111"
    twin.devices.update_device(d1)
    assert twin.devices.get_device("DEV-001").interfaces[0].ip_address == "192.168.1.111"
    print("    [PASS] IP updated successfully.")

    # Test 3: Add Service
    print("\n[3/10] Test 3: Add Service...")
    d1.detailed_services.append(ServiceEntity(name="ssh-client", version="9.3", protocol="TCP", port=0, status="RUNNING"))
    twin.devices.update_device(d1)
    assert any(s.name == "ssh-client" for s in twin.devices.get_device("DEV-001").detailed_services)
    print("    [PASS] Service attached successfully.")

    # Test 4: Add Port
    print("\n[4/10] Test 4: Add Port Listener...")
    d1.detailed_ports.append(PortEntity(port_number=2222, protocol="TCP", state="OPEN", bound_service="ssh-client"))
    twin.devices.update_device(d1)
    assert any(p.port_number == 2222 for p in twin.devices.get_device("DEV-001").detailed_ports)
    print("    [PASS] Port listener registered successfully.")

    # Test 5: Create Connection
    print("\n[5/10] Test 5: Create Topological Connection...")
    d2 = DeviceEntity(
        id="DEV-005",
        hostname="sw-core-01",
        type="SWITCH",
        interfaces=[DeviceInterface(interface_id="vlan1", ip_address="0.0.0.0", mac_address="00:50:56:FE:01:FE", subnet="192.168.1.0/24")],
        criticality=9.0
    )
    twin.register_device(d2)
    conn = ConnectionEntity(connection_id="c-d1-sw", source_device="DEV-001", destination_device="DEV-005")
    twin.register_connection(conn)
    assert twin.connections.get_connection("c-d1-sw") is not None
    print("    [PASS] Connection registered in graph.")

    # Test 6: Assign Vulnerability
    print("\n[6/10] Test 6: Assign Vulnerability...")
    vuln = VulnerabilityEntity(
        vuln_id="VULN-999",
        cve_id="CVE-2024-TEST",
        name="Test Flaw",
        severity="HIGH",
        cvss_score=8.1,
        affected_service="ssh-client",
        status="OPEN"
    )
    twin.vulns.assign_vulnerability_to_device(d1, vuln)
    assert len(twin.vulns.get_device_vulnerabilities(d1)) == 1
    print("    [PASS] Vulnerability bound to device.")

    # Test 7: Change Current State (Operational)
    print("\n[7/10] Test 7: Change Operational Current State...")
    twin.update_device_health("DEV-001", cpu_pct=85.0, mem_pct=60.0, pps=120.0, bps=1000000.0, status="DEGRADED")
    dev = twin.devices.get_device("DEV-001")
    assert dev.current_state.status == "DEGRADED"
    assert dev.current_state.cpu_usage_pct == 85.0
    print("    [PASS] Current state updated.")

    # Test 8: Change Security State
    print("\n[8/10] Test 8: Change Security State...")
    rec = twin.transition_security_state("DEV-001", "SUSPICIOUS", "MANUAL_TEST", "Test audit transition")
    assert rec is not None
    assert twin.devices.get_device("DEV-001").security_state_model.security_status == "SUSPICIOUS"
    print("    [PASS] Security state FSM transitioned to SUSPICIOUS.")

    # Test 9: Receive Telemetry
    print("\n[9/10] Test 9: Ingest Telemetry Metric Event...")
    tel_event = TelemetryMetricEvent(
        device_id="DEV-001",
        metric="packet_rate",
        value=350.0,
        source="SENSOR_TAP_01"
    )
    sync_res = sync.ingest_metric_telemetry(tel_event)
    assert sync_res["status"] == "TELEMETRY_SYNCHRONIZED"
    assert twin.devices.get_device("DEV-001").current_state.network_state.packet_rate_pps == 350.0
    print("    [PASS] Telemetry successfully synchronized.")

    # Test 10: Anomaly -> Security Event -> Twin Update (Closed-Loop)
    print("\n[10/10] Test 10: Closed-Loop Anomaly -> SIEM Event -> Twin Escalation...")
    sec_event = SecurityEvent(
        destination_device_id="DEV-001",
        destination_ip="192.168.1.111",
        source_ip="10.0.0.99",
        protocol="TCP",
        event_type="RATE_SURGE_DETECTED",
        severity="CRITICAL",
        confidence=0.95,
        detection_source="NETWORK_ANOMALY_DETECTOR",
        details={"description": "Packet rate surge exceeded 3-sigma baseline"}
    )
    closed_loop_res = sync.ingest_anomaly_security_event(sec_event)
    assert closed_loop_res["status"] == "SECURITY_STATE_SYNCHRONIZED"
    assert twin.devices.get_device("DEV-001").security_state_model.security_status == "COMPROMISED"
    print("    [PASS] Closed-loop anomaly successfully transitioned Twin to COMPROMISED.")

    print("\n================================================================================")
    print("       ALL 10 INTEGRATION TESTS COMPLETED SUCCESSFULLY                          ")
    print("================================================================================")

if __name__ == "__main__":
    run_10_point_integration()