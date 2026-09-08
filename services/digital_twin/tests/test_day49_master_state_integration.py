import sys
from pathlib import Path
from pydantic import ValidationError
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
)
from packages.shared_types.src.topology import NetworkConnectionModel, ConnectionTypeEnum, ProtocolEnum
from packages.shared_types.src.state_integration import (
    UniversalStateEvent, StateEventSourceEnum, SupportedMetricEnum
)
from packages.shared_types.src.security_state import (
    DynamicVulnerabilityEntity, VulnerabilitySeverityEnum, VulnerabilityLifecycleStatusEnum
)
from packages.shared_types.src.port_service_state import TrackedServiceModel, ServiceDaemonStateEnum

from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.security.firewall_engine import firewall_engine
from services.digital_twin.core.state.state_transition_engine import state_transition_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.core.state.unified_state_coordinator import (
    unified_state_coordinator, DuplicateEventError, OutOfOrderEventError
)

def run_day49_master_suite():
    print("=" * 80)
    print("      PHASE 6 - DAY 49: DUAL-SOURCE STATE & MASTER INTEGRATION AUDIT")
    print("=" * 80 + "\n")

    # Clear runtime states
    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    firewall_engine.clear()
    state_transition_engine.clear()
    performance_state_engine.clear()
    network_state_engine.clear()
    port_service_engine.clear()
    security_state_engine.clear()
    unified_state_coordinator.clear()

    # 1. Provision Canonical Topology
    print("[1/4] Provisioning Full Canonical Topology (Internet -> FW -> RTR -> SW -> Web/DNS/Client/DB)...")
    inet = NetworkDeviceModel(id="inet-01", hostname="INTERNET", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.EXTERNAL)
    fw = NetworkDeviceModel(id="firewall-01", hostname="FIREWALL-01", type=DeviceTypeEnum.FIREWALL, networkZone=NetworkZoneEnum.EXTERNAL)
    rtr = NetworkDeviceModel(id="router-01", hostname="ROUTER-01", type=DeviceTypeEnum.ROUTER, networkZone=NetworkZoneEnum.INTERNAL)
    sw = NetworkDeviceModel(id="switch-01", hostname="SWITCH-01", type=DeviceTypeEnum.SWITCH, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    dns = NetworkDeviceModel(id="dns-01", hostname="DNS-01", type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    db = NetworkDeviceModel(id="db-01", hostname="DB-01", type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])

    for d in [inet, fw, rtr, sw, web, dns, cli, db]:
        device_registry.createDevice(d)

    # Pre-register service and vuln on WEB-01
    port_service_engine.registerService("web-01", TrackedServiceModel(name="HTTPS", protocol="TCP", port=443, status=ServiceDaemonStateEnum.RUNNING))
    security_state_engine.addVulnerability("web-01", DynamicVulnerabilityEntity(
        id="VULN-001", name="TLS Flaw", severity=VulnerabilitySeverityEnum.HIGH, affectedService="HTTPS", status=VulnerabilityLifecycleStatusEnum.OPEN
    ))

    print(f"    [PASS] Provisioned {device_registry.count()} canonical devices.")

    # 2. Sequential Required Tests 1 through 9
    print("\n[2/4] Executing Core State Tests 1 through 9...")
    base_time = datetime.now(timezone.utc)

    # Test 1: Real CPU Update (72%)
    t1 = (base_time + timedelta(seconds=1)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="evt-001", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01",
        metric=SupportedMetricEnum.CPU, value=72, timestamp=t1
    ))
    assert ds.effective.cpu == 72.0
    assert ds.real.cpu == 72.0
    print("    [PASS] Test 1: Real CPU = 72% -> Twin CPU = 72%")

    # Test 2: Real Memory Update (68%)
    t2 = (base_time + timedelta(seconds=2)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="evt-002", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01",
        metric=SupportedMetricEnum.MEMORY, value=68, timestamp=t2
    ))
    assert ds.effective.memory == 68.0
    assert ds.real.memory == 68.0
    print("    [PASS] Test 2: Real Memory = 68% -> Twin Memory = 68%")

    # Test 3: Real Network Utilisation Update (55%)
    t3 = (base_time + timedelta(seconds=3)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="evt-003", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01",
        metric=SupportedMetricEnum.NETWORK_UTILISATION, value=55, timestamp=t3
    ))
    assert ds.effective.networkUtilisation == 55.0
    print("    [PASS] Test 3: Network Utilisation = 55% -> Twin = 55%")

    # Test 4: Connections Update (20)
    t4 = (base_time + timedelta(seconds=4)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="evt-004", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01",
        metric=SupportedMetricEnum.CONNECTIONS, value=20, timestamp=t4
    ))
    assert ds.effective.activeConnections == 20
    print("    [PASS] Test 4: Active Connections = 20 -> Twin = 20")

    # Test 5: Simulation - Port 443 Closed
    t5 = (base_time + timedelta(seconds=5)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="sim-001", source=StateEventSourceEnum.SIMULATION, deviceId="web-01",
        metric=SupportedMetricEnum.OPEN_PORT, value={"port": 443, "state": "CLOSED"}, timestamp=t5
    ))
    assert 443 not in ds.effective.openPorts
    print("    [PASS] Test 5: Port 443 -> CLOSED via Simulation -> Twin: 443 CLOSED")

    # Test 6: Simulation - Service HTTPS Stopped
    t6 = (base_time + timedelta(seconds=6)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="sim-002", source=StateEventSourceEnum.SIMULATION, deviceId="web-01",
        metric=SupportedMetricEnum.SERVICE_STATUS, value={"name": "HTTPS", "status": "STOPPED"}, timestamp=t6
    ))
    assert ds.effective.services["HTTPS"] == "STOPPED"
    print("    [PASS] Test 6: Service HTTPS -> STOPPED via Simulation -> Twin: HTTPS STOPPED")

    # Test 7: Anomaly Event - Security Status SUSPICIOUS
    t7 = (base_time + timedelta(seconds=7)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="evt-007", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01",
        metric=SupportedMetricEnum.SECURITY_STATUS, value="SUSPICIOUS", timestamp=t7
    ))
    assert ds.effective.securityStatus == "SUSPICIOUS"
    print("    [PASS] Test 7: Security NORMAL -> SUSPICIOUS -> Twin Security: SUSPICIOUS")

    # Test 8: Simulation - Vulnerability Status PATCHED
    t8 = (base_time + timedelta(seconds=8)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="sim-003", source=StateEventSourceEnum.SIMULATION, deviceId="web-01",
        metric=SupportedMetricEnum.VULNERABILITY_STATUS, value={"id": "VULN-001", "status": "PATCHED"}, timestamp=t8
    ))
    assert ds.effective.vulnerabilities["VULN-001"] == "PATCHED"
    print("    [PASS] Test 8: Vulnerability VULN-001 -> PATCHED -> Twin: PATCHED")

    # Test 9: Device Failure Simulation - WEB-01 OFFLINE
    t9 = (base_time + timedelta(seconds=9)).isoformat()
    ds = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="sim-004", source=StateEventSourceEnum.SIMULATION, deviceId="web-01",
        metric=SupportedMetricEnum.DEVICE_STATE, value="OFFLINE", timestamp=t9
    ))
    assert ds.effective.operationalState == "OFFLINE"
    print("    [PASS] Test 9: Device Failure -> OFFLINE -> Twin: OFFLINE")

    # 3. Source Precedence & Conflict Resolution
    print("\n[3/4] Testing Real vs. Simulation Conflict Resolution...")
    t10 = (base_time + timedelta(seconds=10)).isoformat()
    # Real reports 40% CPU
    unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="evt-real-cpu", source=StateEventSourceEnum.REAL_NETWORK, deviceId="db-01",
        metric=SupportedMetricEnum.CPU, value=40.0, timestamp=t10
    ))
    # Simulation injects 95% CPU Spike
    t11 = (base_time + timedelta(seconds=11)).isoformat()
    db_state = unified_state_coordinator.ingestEvent(UniversalStateEvent(
        eventId="sim-high-cpu", source=StateEventSourceEnum.SIMULATION, deviceId="db-01",
        metric=SupportedMetricEnum.CPU, value=95.0, timestamp=t11
    ))
    print(f"    DB-01 State Partition: Real CPU = {db_state.real.cpu}%, Simulation CPU = {db_state.simulation.cpu}%, Effective CPU = {db_state.effective.cpu}%")
    assert db_state.real.cpu == 40.0
    assert db_state.simulation.cpu == 95.0
    assert db_state.effective.cpu == 95.0
    assert db_state.effective.performanceLevel == "CRITICAL"
    print("    [PASS] Precedence policy accurately maintained: Effective reflects simulation while preserving real.")

    # 4. Failure-Test Matrix (14 Boundary Rejections)
    print("\n[4/4] Executing Complete Failure-Test Matrix (14 Conditions)...")

    # 1. Unknown device
    try:
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="f-1", source=StateEventSourceEnum.REAL_NETWORK, deviceId="ghost-dev", metric=SupportedMetricEnum.CPU, value=50
        ))
        assert False
    except DeviceNotFoundError:
        print("    [1/14] [PASS] Rejected unknown device.")

    # 2. Invalid CPU (negative)
    try:
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="f-2", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.CPU, value=-5
        ))
        assert False
    except ValueError:
        print("    [2/14] [PASS] Rejected negative CPU.")

    # 3. CPU > 100
    try:
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="f-3", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.CPU, value=105
        ))
        assert False
    except ValueError:
        print("    [3/14] [PASS] Rejected CPU > 100%.")

    # 4. Memory > 100
    try:
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="f-4", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.MEMORY, value=120
        ))
        assert False
    except ValueError:
        print("    [4/14] [PASS] Rejected Memory > 100%.")

    # 5. Negative Utilisation
    try:
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="f-5", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.NETWORK_UTILISATION, value=-1
        ))
        assert False
    except ValueError:
        print("    [5/14] [PASS] Rejected negative network utilisation.")

    # 6. Unknown connection (simulating session failure on non-existent link)
    try:
        network_state_engine.failConnection("non-existent-conn-999")
        assert False
    except KeyError:
        print("    [6/14] [PASS] Rejected unknown connection failure.")

    # 7. Unknown port (closing port not configured)
    try:
        port_service_engine.closePort("dns-01", 9999)
        assert False
    except KeyError:
        print("    [7/14] [PASS] Rejected unknown port query.")

    # 8. Unknown service (stopping unconfigured daemon)
    try:
        port_service_engine.stopService("dns-01", "ghost-daemon")
        assert False
    except KeyError:
        print("    [8/14] [PASS] Rejected unknown service query.")

    # 9. Invalid security state
    try:
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="f-9", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.SECURITY_STATUS, value="SUPER_DANGEROUS"
        ))
        assert False
    except ValueError:
        print("    [9/14] [PASS] Rejected invalid security state string.")

    # 10. Invalid vulnerability state
    try:
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="f-10", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.VULNERABILITY_STATUS, value="COMPLETELY_CURED"
        ))
        assert False
    except ValueError:
        print("    [10/14] [PASS] Rejected invalid vulnerability state string.")

    # 11. Missing timestamp
    try:
        UniversalStateEvent(
            eventId="f-11", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.CPU, value=50, timestamp=""
        )
        assert False
    except ValidationError:
        print("    [11/14] [PASS] Rejected event with empty timestamp.")

    # 12. Duplicate event
    try:
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="evt-001", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.CPU, value=72
        ))
        assert False
    except DuplicateEventError:
        print("    [12/14] [PASS] Rejected duplicate event ID.")

    # 13. Out-of-order event
    try:
        old_time = (base_time - timedelta(hours=5)).isoformat()
        unified_state_coordinator.ingestEvent(UniversalStateEvent(
            eventId="f-13", source=StateEventSourceEnum.REAL_NETWORK, deviceId="web-01", metric=SupportedMetricEnum.CPU, value=50, timestamp=old_time
        ))
        assert False
    except OutOfOrderEventError:
        print("    [13/14] [PASS] Rejected out-of-order event.")

    # 14. Conflicting real/simulation state handled safely
    assert db_state.real.cpu != db_state.simulation.cpu
    print("    [14/14] [PASS] Conflicting real/simulation states successfully resolved via policy.")

    # Audit history validation
    history = unified_state_coordinator.getAuditHistory("web-01")
    print(f"\n[*] Audit Trail: {len(history)} universal state events recorded for WEB-01.")
    assert len(history) >= 9

    print("\n" + "=" * 80)
    print("   ALL PHASE 6 DAY 49 DUAL-SOURCE TESTS & FAILURE MATRIX PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day49_master_suite()