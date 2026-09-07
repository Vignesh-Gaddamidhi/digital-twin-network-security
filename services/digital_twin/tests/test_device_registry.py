import sys
from pathlib import Path
from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum, NetworkInterfaceConfig
)
from services.digital_twin.core.devices.network_device_registry import (
    NetworkDeviceRegistry, DeviceAlreadyExistsError, DeviceNotFoundError
)

def run_device_registry_suite():
    print("================================================================================")
    print("       WEEK 5 - DAY 29: NETWORK DEVICE REGISTRY VALIDATION AUDIT                ")
    print("================================================================================\n")

    registry = NetworkDeviceRegistry()

    # 1. Create Valid Device (Server in DMZ)
    print("[1/8] Testing Valid Device Creation (Web Server in DMZ)...")
    server = NetworkDeviceModel(
        id="server-web-01",
        hostname="web-server-01",
        type=DeviceTypeEnum.SERVER,
        role="WEB_SERVER",
        ipAddresses=["192.168.10.20"],
        macAddresses=["AA:BB:CC:DD:EE:01"],
        interfaces=[
            NetworkInterfaceConfig(
                interface_id="eth0",
                ip_address="192.168.10.20",
                mac_address="AA:BB:CC:DD:EE:01",
                subnet_cidr="192.168.10.0/24"
            )
        ],
        operatingSystem="Ubuntu",
        networkZone=NetworkZoneEnum.DMZ,
        ports=[80, 443],
        services=["nginx"]
    )
    created = registry.createDevice(server)
    assert created.id == "server-web-01"
    assert registry.count() == 1
    print(f"    [PASS] Successfully registered: {created.hostname} ({created.id}) in {created.networkZone.value}")

    # 2. Duplicate Device ID Rejection
    print("\n[2/8] Testing Duplicate Device ID Rejection...")
    try:
        registry.createDevice(server)
        assert False, "Failed to reject duplicate device ID!"
    except DeviceAlreadyExistsError as e:
        print(f"    [PASS] Safely rejected duplicate ID: {e}")

    # 3. Missing / Invalid Hostname Rejection
    print("\n[3/8] Testing Missing / Invalid Hostname Rejection...")
    try:
        NetworkDeviceModel(
            id="client-01",
            hostname="",  # Invalid empty hostname
            type=DeviceTypeEnum.CLIENT
        )
        assert False, "Failed to reject invalid empty hostname!"
    except ValidationError as e:
        print(f"    [PASS] Pydantic rejected empty hostname.")

    # 4. Invalid Device Type Rejection
    print("\n[4/8] Testing Invalid Device Type Rejection...")
    try:
        NetworkDeviceModel(
            id="device-unknown",
            hostname="unknown-node",
            type="SUPER_QUANTUM_MAINFRAME"  # Invalid enum value
        )
        assert False, "Failed to reject invalid device type!"
    except ValidationError as e:
        print(f"    [PASS] Pydantic rejected invalid device type.")

    # 5. Invalid IP Address Format Rejection
    print("\n[5/8] Testing Invalid IP Address Rejection...")
    try:
        NetworkDeviceModel(
            id="router-01",
            hostname="rtr-edge",
            type=DeviceTypeEnum.ROUTER,
            ipAddresses=["999.888.777.666"]  # Malformed IP
        )
        assert False, "Failed to reject malformed IP address!"
    except ValidationError as e:
        print(f"    [PASS] Pydantic rejected malformed IP address: 999.888.777.666")

    # 6. Invalid MAC Address Format Rejection
    print("\n[6/8] Testing Invalid MAC Address Rejection...")
    try:
        NetworkDeviceModel(
            id="switch-01",
            hostname="sw-core",
            type=DeviceTypeEnum.SWITCH,
            macAddresses=["NOT-A-REAL-MAC-ADDRESS"]
        )
        assert False, "Failed to reject malformed MAC address!"
    except ValidationError as e:
        print(f"    [PASS] Pydantic rejected malformed MAC address.")

    # 7. Delete Existing Device
    print("\n[7/8] Testing Delete Existing Device...")
    deleted = registry.deleteDevice("server-web-01")
    assert deleted is True
    assert registry.count() == 0
    print("    [PASS] Successfully deleted existing device.")

    # 8. Delete Unknown Device Rejection
    print("\n[8/8] Testing Delete Unknown Device Rejection...")
    try:
        registry.deleteDevice("ghost-device-999")
        assert False, "Failed to reject deletion of non-existent device!"
    except DeviceNotFoundError as e:
        print(f"    [PASS] Safely rejected deletion of non-existent device: {e}")

    print("\n================================================================================")
    print("       ALL 8 DEVICE REGISTRY TESTS PASSED CLEANLY                               ")
    print("================================================================================")

if __name__ == "__main__":
    run_device_registry_suite()