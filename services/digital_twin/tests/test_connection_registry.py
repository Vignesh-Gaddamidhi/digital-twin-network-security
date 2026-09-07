import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import (
    NetworkConnectionModel, ConnectionTypeEnum, ConnectionStatusEnum, ProtocolEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.connections.network_connection_registry import (
    connection_registry, ConnectionAlreadyExistsError, ConnectionNotFoundError
)

def run_connection_registry_suite():
    print("================================================================================")
    print("       WEEK 5 - DAY 31: NETWORK CONNECTION REGISTRY VALIDATION AUDIT            ")
    print("================================================================================\n")

    device_registry.clear()
    connection_registry.clear()

    # Pre-populate two devices for valid connection testing
    print("[Setup] Provisioning router-01 and server-web-01 into Device Registry...")
    router = NetworkDeviceModel(
        id="router-01",
        hostname="rtr-gw-01",
        type=DeviceTypeEnum.ROUTER,
        ipAddresses=["192.168.10.1"],
        networkZone=NetworkZoneEnum.EXTERNAL
    )
    server = NetworkDeviceModel(
        id="server-web-01",
        hostname="web-server-01",
        type=DeviceTypeEnum.SERVER,
        ipAddresses=["192.168.10.20"],
        networkZone=NetworkZoneEnum.DMZ,
        ports=[443]
    )
    device_registry.createDevice(router)
    device_registry.createDevice(server)
    print("    [+] Setup complete.\n")

    # 1. Create Valid Connection
    print("[1/8] Testing Valid Connection Creation (router-01 -> server-web-01:443/TCP)...")
    conn1 = NetworkConnectionModel(
        id="conn-001",
        sourceDevice="router-01",
        destinationDevice="server-web-01",
        protocol=ProtocolEnum.TCP,
        destinationPort=443,
        connectionType=ConnectionTypeEnum.NETWORK,
        status=ConnectionStatusEnum.ACTIVE,
        bandwidth=1000.0,
        latency=0.5
    )
    created = connection_registry.createConnection(conn1)
    assert created.id == "conn-001"
    assert connection_registry.count() == 1
    # Verify auto-attachment to device
    assert "conn-001" in device_registry.getDevice("router-01").connections
    assert "conn-001" in device_registry.getDevice("server-web-01").connections
    print(f"    [PASS] Created: {created.id} ({created.sourceDevice} -> {created.destinationDevice})")

    # 2. Rejection: Unknown Source Device
    print("\n[2/8] Testing Unknown Source Device Rejection...")
    try:
        connection_registry.createConnection(NetworkConnectionModel(
            id="conn-invalid-src",
            sourceDevice="ghost-router",
            destinationDevice="server-web-01",
            destinationPort=443
        ))
        assert False, "Failed to reject unknown source device!"
    except DeviceNotFoundError as e:
        print(f"    [PASS] Safely rejected unknown source: {e}")

    # 3. Rejection: Unknown Destination Device
    print("\n[3/8] Testing Unknown Destination Device Rejection...")
    try:
        connection_registry.createConnection(NetworkConnectionModel(
            id="conn-invalid-dst",
            sourceDevice="router-01",
            destinationDevice="ghost-server",
            destinationPort=443
        ))
        assert False, "Failed to reject unknown destination device!"
    except DeviceNotFoundError as e:
        print(f"    [PASS] Safely rejected unknown destination: {e}")

    # 4. Rejection: Self-Loop Connection
    print("\n[4/8] Testing Self-Loop Connection Rejection...")
    try:
        NetworkConnectionModel(
            id="conn-loop",
            sourceDevice="router-01",
            destinationDevice="router-01"
        )
        assert False, "Failed to reject self-loop connection!"
    except ValidationError as e:
        print("    [PASS] Pydantic rejected self-loop connection.")

    # 5. Rejection: Duplicate Connection ID
    print("\n[5/8] Testing Duplicate Connection ID Rejection...")
    try:
        connection_registry.createConnection(conn1)
        assert False, "Failed to reject duplicate connection ID!"
    except ConnectionAlreadyExistsError as e:
        print(f"    [PASS] Safely rejected duplicate ID: {e}")

    # 6. Rejection: Redundant Parallel Link
    print("\n[6/8] Testing Redundant Parallel Active Link Rejection...")
    try:
        connection_registry.createConnection(NetworkConnectionModel(
            id="conn-002",
            sourceDevice="router-01",
            destinationDevice="server-web-01",
            protocol=ProtocolEnum.TCP,
            destinationPort=443,
            connectionType=ConnectionTypeEnum.NETWORK
        ))
        assert False, "Failed to reject redundant active parallel link!"
    except ConnectionAlreadyExistsError as e:
        print(f"    [PASS] Safely blocked parallel active link: {e}")

    # 7. Update Connection (Status & Latency)
    print("\n[7/8] Testing Update Connection Parameters...")
    conn1.status = ConnectionStatusEnum.DEGRADED
    conn1.latency = 15.8
    updated = connection_registry.updateConnection(conn1)
    assert updated.status == ConnectionStatusEnum.DEGRADED
    assert updated.latency == 15.8
    print(f"    [PASS] Updated: status={updated.status.value}, latency={updated.latency}ms")

    # 8. Delete Connection
    print("\n[8/8] Testing Delete Connection & Device Detachment...")
    deleted = connection_registry.deleteConnection("conn-001")
    assert deleted is True
    assert connection_registry.count() == 0
    assert "conn-001" not in device_registry.getDevice("router-01").connections
    assert "conn-001" not in device_registry.getDevice("server-web-01").connections
    print("    [PASS] Connection deleted and detached from device reference lists.")

    print("\n================================================================================")
    print("       ALL 8 CONNECTION REGISTRY TESTS PASSED CLEANLY                           ")
    print("================================================================================")

if __name__ == "__main__":
    run_connection_registry_suite()