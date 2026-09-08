import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.ssh_traffic import (
    SshSessionStateEnum, SshAuthMethodEnum, SshTrafficProfile, SshTransactionEvent
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.simulation.generators.ssh_traffic_generator import (
    ssh_orchestrator, SshTargetPortClosedError
)

def run_ssh_traffic_suite():
    print("=" * 80)
    print("       WEEK 8 - DAY 55: ADMINISTRATIVE SSH TRAFFIC SIMULATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    ssh_orchestrator.clear()

    # 1. Provision Canonical Devices
    print("[1/5] Registering Admin Workstation and Target Servers in Registry...")
    admin = NetworkDeviceModel(id="admin-01", hostname="ADMIN-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    server = NetworkDeviceModel(id="server-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[22, 443])
    device_registry.createDevice(admin)
    device_registry.createDevice(server)
    device_registry.createDevice(web)
    print("    [PASS] Registered admin-01, server-01, and web-01.")

    # 2. Test Normal Successful SSH Session Lifecycle
    print("\n[2/5] Testing Normal Successful SSH Session (REQUESTED -> AUTHENTICATING -> ESTABLISHED -> IDLE -> CLOSED)...")
    session_events = ssh_orchestrator.generator.generateSessionSequence(
        source_dev="admin-01",
        dest_dev="server-01",
        username="sysadmin",
        auth_method=SshAuthMethodEnum.PUBLIC_KEY,
        destination_port=22,
        should_fail=False,
        simulation_id="sim-day55"
    )

    states = [e.sessionState for e in session_events]
    print(f"    Observed Sequence: {[s.value for s in states]}")
    assert len(session_events) == 5
    assert states[0] == SshSessionStateEnum.REQUESTED
    assert states[1] == SshSessionStateEnum.AUTHENTICATING
    assert states[2] == SshSessionStateEnum.ESTABLISHED
    assert states[3] == SshSessionStateEnum.IDLE
    assert states[4] == SshSessionStateEnum.CLOSED

    for e in session_events:
        assert e.destinationPort == 22
        assert e.application == "SSH"
        assert e.protocol == "TCP"
        assert e.username == "sysadmin"
        assert e.authMethod == SshAuthMethodEnum.PUBLIC_KEY

    print("    [PASS] Successful SSH session lifecycle verified.")

    # 3. Test Failed SSH Session (Authentication Failure)
    print("\n[3/5] Testing Failed SSH Session (should_fail=True -> FAILED)...")
    fail_events = ssh_orchestrator.generator.generateSessionSequence(
        source_dev="admin-01",
        dest_dev="server-01",
        username="guest",
        auth_method=SshAuthMethodEnum.PASSWORD,
        should_fail=True,
        simulation_id="sim-day55"
    )

    fail_states = [e.sessionState for e in fail_events]
    print(f"    Observed Failed Sequence: {[s.value for s in fail_states]}")
    assert len(fail_events) == 3
    assert fail_states == [
        SshSessionStateEnum.REQUESTED,
        SshSessionStateEnum.AUTHENTICATING,
        SshSessionStateEnum.FAILED
    ]
    assert fail_events[-1].details["reason"] == "Permission denied (publickey)"
    print("    [PASS] Failed SSH session accurately terminated with FAILED state.")

    # 4. Multi-Server SshTrafficProfile Execution
    print("\n[4/5] Testing SshTrafficProfile Execution Across Multiple Servers...")
    profile = SshTrafficProfile(
        name="Admin-Maintenance-Run",
        sourceAdmin="admin-01",
        targetServers=["server-01", "web-01"],
        authMethod=SshAuthMethodEnum.PUBLIC_KEY,
        failureRate=0.0
    )
    profile_events = ssh_orchestrator.generateFromProfile(profile, simulation_id="sim-day55")
    print(f"    Total Events Emitted: {len(profile_events)} across {len(profile.targetServers)} servers.")
    assert len(profile_events) == 10  # 5 steps * 2 servers
    print("    [PASS] Multi-server administrative SSH profile execution verified.")

    # 5. Boundary Invariant & Rejection Tests
    print("\n[5/5] Executing Boundary Invariant & Rejection Tests...")

    # Unknown server rejection
    try:
        ssh_orchestrator.generator.generateSessionSequence("admin-01", "ghost-server")
        assert False
    except DeviceNotFoundError:
        print("    [PASS] Safely rejected unknown destination server.")

    # Invalid port validation (< 1 or out-of-range privileged port)
    try:
        SshTransactionEvent(
            sourceDevice="admin-01", destinationDevice="server-01", destinationPort=23
        )
        assert False
    except ValidationError:
        print("    [PASS] Safely rejected invalid SSH port (Port 23 is Telnet, not SSH).")

    # Audit ledger check
    history = ssh_orchestrator.getEvents()
    assert len(history) >= 10
    print(f"    [PASS] Verified {len(history)} persistent SSH events in history ledger.")

    print("\n" + "=" * 80)
    print("       ALL DAY 55 SSH TRAFFIC SIMULATION TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_ssh_traffic_suite()