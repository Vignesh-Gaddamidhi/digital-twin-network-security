import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum, NetworkInterfaceConfig, RouteEntryConfig
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.devices.device_configuration_engine import config_engine

def run_configuration_engine_suite():
    print("================================================================================")
    print("       WEEK 5 - DAY 30: DYNAMIC DEVICE CONFIGURATION & HISTORY AUDIT            ")
    print("================================================================================\n")

    device_registry.clear()
    config_engine.clearHistory()

    # 1. Base Device Initialization
    print("[1/6] Registering Baseline Server (web-server-01 at 192.168.10.20:80 in DMZ)...")
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
        ports=[80],
        services=["nginx"]
    )
    device_registry.createDevice(server)
    print(f"    [+] Initial State: IPs={server.ipAddresses} | Ports={server.ports} | Zone={server.networkZone.value}")

    # 2. Reassign IP Address (T1 -> T2)
    print("\n[2/6] Reconfiguring Primary IP (192.168.10.20 -> 192.168.10.30)...")
    config_engine.assignIPAddress("server-web-01", "192.168.10.30", interface_id="eth0", reason="Subnet migration")
    d_updated = device_registry.getDevice("server-web-01")
    assert "192.168.10.30" in d_updated.ipAddresses
    assert d_updated.interfaces[0].ip_address == "192.168.10.30"
    print(f"    [PASS] IP Reassigned. Active IPs: {d_updated.ipAddresses}")

    # 3. Open Port & Deploy SSL Service (T3)
    print("\n[3/6] Opening Port 443 and Adding HTTPS SSL Service...")
    config_engine.openPort("server-web-01", 443, reason="Enable HTTPS listener")
    config_engine.addService("server-web-01", "nginx-ssl", reason="Deploy SSL reverse proxy")
    d_updated = device_registry.getDevice("server-web-01")
    assert 443 in d_updated.ports
    assert "nginx-ssl" in d_updated.services
    print(f"    [PASS] Ports: {d_updated.ports} | Services: {d_updated.services}")

    # 4. Stop Plain HTTP Service (T4)
    print("\n[4/6] Terminating Insecure HTTP Service and Closing Port 80...")
    config_engine.removeService("server-web-01", "nginx", reason="Enforce HTTPS only")
    config_engine.closePort("server-web-01", 80, reason="Drop unencrypted HTTP")
    d_updated = device_registry.getDevice("server-web-01")
    assert "nginx" not in d_updated.services
    assert 80 not in d_updated.ports
    print(f"    [PASS] Ports: {d_updated.ports} | Services: {d_updated.services}")

    # 5. Zone Relocation & Static Route Injection (T5 & T6)
    print("\n[5/6] Migrating Zone to INTERNAL and Injecting Default Route...")
    config_engine.changeZone("server-web-01", NetworkZoneEnum.INTERNAL, reason="Relocated behind WAF proxy")
    config_engine.addRoute(
        "server-web-01",
        RouteEntryConfig(destination_cidr="0.0.0.0/0", gateway_ip="192.168.10.1", interface_id="eth0", metric=10),
        reason="Default gateway route"
    )
    d_updated = device_registry.getDevice("server-web-01")
    assert d_updated.networkZone == NetworkZoneEnum.INTERNAL
    assert len(d_updated.routes) == 1
    assert d_updated.routes[0].gateway_ip == "192.168.10.1"
    print(f"    [PASS] Zone: {d_updated.networkZone.value} | Routes: {d_updated.routes[0].destination_cidr} via {d_updated.routes[0].gateway_ip}")

    # 6. Audit Immutable Configuration History
    print("\n[6/6] Auditing Immutable Configuration History Ledger...")
    history = config_engine.getConfigurationHistory("server-web-01")
    print(f"    Total Mutations Tracked: {len(history)}")
    for h in history:
        print(f"    - [{h.action:20s}] Field: {h.field_changed:18s} | Prev: {str(h.previous_value):20s} -> New: {str(h.new_value):20s} | Reason: {h.reason}")

    assert len(history) >= 6, f"Expected at least 6 history records, got {len(history)}"
    assert history[0].action == "ASSIGN_IP"
    assert history[1].action == "OPEN_PORT"
    assert history[-2].action == "CHANGE_ZONE"
    assert history[-1].action == "ADD_ROUTE"

    print("\n================================================================================")
    print("      DEVICE CONFIGURATION ENGINE & AUDIT TRAIL VERIFIED SUCCESSFULLY           ")
    print("================================================================================")

if __name__ == "__main__":
    run_configuration_engine_suite()