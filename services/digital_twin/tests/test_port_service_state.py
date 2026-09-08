import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.port_service_state import (
    PortStateEnum, ServiceDaemonStateEnum, TrackedPortModel, TrackedServiceModel
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.state.port_service_engine import (
    port_service_engine, PortNotFoundError, ServiceNotFoundError, DuplicateServiceError
)

def run_port_service_suite():
    print("=" * 80)
    print("       WEEK 7 - DAY 47: OPEN PORTS & SERVICES STATE ENGINE AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    port_service_engine.clear()

    # 1. Provision Canonical Devices
    print("[1/6] Provisioning Host Infrastructure (WEB-01, DB-01)...")
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ)
    db = NetworkDeviceModel(id="db-01", hostname="DB-01", type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL)
    device_registry.createDevice(web)
    device_registry.createDevice(db)
    print("    [PASS] Provisioned WEB-01 and DB-01 in registry.")

    # 2. Port State Management & Dynamic Open Port Event
    print("\n[2/6] Initializing Ports 80, 443 on WEB-01, and Opening Port 8080...")
    port_service_engine.openPort("web-01", 80, protocol="TCP", service_name="HTTP")
    port_service_engine.openPort("web-01", 443, protocol="TCP", service_name="HTTPS")
    
    initial_ports = [p.port for p in port_service_engine.listPorts("web-01")]
    assert sorted(initial_ports) == [80, 443]
    print(f"    Initial Open Ports: {initial_ports}")

    # Dynamic event: Open port 8080
    port_service_engine.openPort("web-01", 8080, protocol="TCP", service_name="alt-http", reason="Dev deployment")
    updated_ports = [p.port for p in port_service_engine.listPorts("web-01") if p.state == PortStateEnum.OPEN]
    assert sorted(updated_ports) == [80, 443, 8080]
    print(f"    [PASS] Dynamically opened port 8080. Current active: {updated_ports}")

    # Verify device registry sync
    dev_web = device_registry.getDevice("web-01")
    assert 8080 in dev_web.ports

    # 3. Port State Toggling (Close Port 80, Filter Port 8080)
    print("\n[3/6] Testing Port State Toggling (CLOSE Port 80, FILTER Port 8080)...")
    closed_p80 = port_service_engine.closePort("web-01", 80, reason="Drop unencrypted HTTP")
    assert closed_p80.state == PortStateEnum.CLOSED

    filtered_p8080 = port_service_engine.setPortState("web-01", 8080, PortStateEnum.FILTERED, reason="Firewall dropped")
    assert filtered_p8080.state == PortStateEnum.FILTERED

    open_after = [p.port for p in port_service_engine.listPorts("web-01") if p.state == PortStateEnum.OPEN]
    assert open_after == [443]
    print(f"    [PASS] Port 80 is CLOSED, Port 8080 is FILTERED. Only {open_after} remains OPEN.")

    # 4. Service Daemon Registration & Binding
    print("\n[4/6] Registering Service Daemons (nginx on WEB-01:443, postgresql on DB-01:5432)...")
    srv_nginx = port_service_engine.registerService("web-01", TrackedServiceModel(
        name="nginx", protocol="TCP", port=443, status=ServiceDaemonStateEnum.RUNNING, version="1.24.0"
    ))
    srv_pg = port_service_engine.registerService("db-01", TrackedServiceModel(
        name="postgresql", protocol="TCP", port=5432, status=ServiceDaemonStateEnum.RUNNING, version="16.1"
    ))

    assert srv_nginx.status == ServiceDaemonStateEnum.RUNNING
    assert srv_pg.status == ServiceDaemonStateEnum.RUNNING
    assert port_service_engine.getPort("db-01", 5432).state == PortStateEnum.OPEN
    print("    [PASS] Services running and bound to socket listeners.")

    # 5. Service Failure & Cascading Port Disruption
    print("\n[5/6] Testing Service Failure Propagation (nginx STOPPED/FAILED -> Port 443 CLOSED)...")
    # Stop nginx service
    stopped_srv = port_service_engine.stopService("web-01", "nginx", reason="Simulated maintenance shutdown")
    assert stopped_srv.status == ServiceDaemonStateEnum.STOPPED

    # Port 443 must cascade to CLOSED
    p443 = port_service_engine.getPort("web-01", 443)
    assert p443.state == PortStateEnum.CLOSED
    print("    [PASS] Stopped service 'nginx' automatically cascaded Port 443 to CLOSED.")

    # Fail PostgreSQL service
    failed_pg = port_service_engine.failService("db-01", "postgresql", reason="OOM killer killed postmaster")
    assert failed_pg.status == ServiceDaemonStateEnum.FAILED
    assert port_service_engine.getPort("db-01", 5432).state == PortStateEnum.CLOSED
    print("    [PASS] Failed service 'postgresql' automatically cascaded Port 5432 to CLOSED.")

    # 6. Boundary Invariant & Rejection Tests
    print("\n[6/6] Executing Boundary Invariant & Rejection Suite...")

    # Unknown device
    try:
        port_service_engine.openPort("ghost-dev", 9000)
        assert False
    except DeviceNotFoundError:
        print("    [PASS] Rejected unknown device.")

    # Unknown port query
    try:
        port_service_engine.getPort("web-01", 9999)
        assert False
    except PortNotFoundError:
        print("    [PASS] Rejected non-existent port query.")

    # Unknown service query
    try:
        port_service_engine.getService("web-01", "ghost-service")
        assert False
    except ServiceNotFoundError:
        print("    [PASS] Rejected non-existent service query.")

    # Duplicate service registration
    try:
        port_service_engine.registerService("web-01", TrackedServiceModel(name="nginx", port=443))
        assert False
    except DuplicateServiceError:
        print("    [PASS] Rejected duplicate service name registration.")

    # Invalid port validation (< 1 or > 65535)
    try:
        TrackedPortModel(port=70000, protocol="TCP")
        assert False
    except ValidationError:
        print("    [PASS] Rejected out-of-range port (>65535).")

    # Invalid protocol
    try:
        TrackedPortModel(port=80, protocol="BLUETOOTH")
        assert False
    except ValidationError:
        print("    [PASS] Rejected unsupported protocol.")

    # Audit events inspection
    events = port_service_engine.getAuditEvents("web-01")
    print(f"\n[*] Audit Trail: Recorded {len(events)} state change events for WEB-01.")
    assert len(events) >= 5

    print("\n" + "=" * 80)
    print("       ALL DAY 47 PORT & SERVICE STATE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_port_service_suite()