import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.switch import PortStatusEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.topology.switch_engine import switch_engine

def run_switch_model_suite():
    print("================================================================================")
    print("       WEEK 5 - DAY 33: SWITCH BEHAVIOR & CAM TABLE AUDIT                       ")
    print("================================================================================")

    device_registry.clear()

    # 1. Setup Lab Switch and Endpoints
    print("[1/6] Provisioning Switch (sw-core) and 3 Connected Hosts...")
    switch_dev = NetworkDeviceModel(id="sw-core", hostname="sw-core-01", type=DeviceTypeEnum.SWITCH)
    pc1 = NetworkDeviceModel(id="pc-01", hostname="pc-01", type=DeviceTypeEnum.CLIENT, macAddresses=["AA:BB:CC:01:01:01"])
    pc2 = NetworkDeviceModel(id="pc-02", hostname="pc-02", type=DeviceTypeEnum.CLIENT, macAddresses=["AA:BB:CC:01:01:02"])
    srv = NetworkDeviceModel(id="srv-01", hostname="srv-web", type=DeviceTypeEnum.SERVER, macAddresses=["AA:BB:CC:01:01:10"])

    for d in [switch_dev, pc1, pc2, srv]:
        device_registry.createDevice(d)

    # 2. Connect Devices to Switch Ports
    print("\n[2/6] Connecting Devices to Switch Ports (Port 1: PC1, Port 2: PC2, Port 3: Server)...")
    p1 = switch_engine.connectDeviceToSwitch("sw-core", 1, "pc-01", "AA:BB:CC:01:01:01")
    p2 = switch_engine.connectDeviceToSwitch("sw-core", 2, "pc-02", "AA:BB:CC:01:01:02")
    p3 = switch_engine.connectDeviceToSwitch("sw-core", 3, "srv-01", "AA:BB:CC:01:01:10")

    assert p1.status == PortStatusEnum.UP
    assert p1.connected_device_id == "pc-01"
    print("    [PASS] Switch ports connected and active.")

    # 3. Verify Initial CAM Table
    print("\n[3/6] Auditing Learned CAM Table Entries...")
    cam_entries = switch_engine.getMacTable("sw-core")
    print(f"    Learned MACs Count: {len(cam_entries)}")
    for entry in cam_entries:
        print(f"    - MAC: {entry.mac_address} -> Port: {entry.port_number} (VLAN: {entry.vlan_id})")

    assert len(cam_entries) == 3
    assert switch_engine.lookupMacAddress("sw-core", "AA:BB:CC:01:01:01").port_number == 1
    assert switch_engine.lookupMacAddress("sw-core", "AA:BB:CC:01:01:10").port_number == 3
    print("    [PASS] CAM table accurately maps all 3 physical ports.")

    # 4. Unicast Forwarding: PC1 -> Server (Port 1 -> Port 3)
    print("\n[4/6] Testing Known Unicast Forwarding (PC1 -> Server)...")
    res_unicast = switch_engine.processEthernetFrame(
        switch_id="sw-core",
        ingress_port=1,
        source_mac="AA:BB:CC:01:01:01",
        destination_mac="AA:BB:CC:01:01:10"
    )
    print(f"    Action: {res_unicast.forwarding_action} | Egress Ports: {res_unicast.egress_ports}")
    print(f"    Detail: {res_unicast.explanation}")
    assert res_unicast.forwarding_action == "FORWARD_UNICAST"
    assert res_unicast.egress_ports == [3]
    print("    [PASS] Known unicast routed directly to Port 3 without flooding.")

    # 5. Unknown Unicast Flooding
    print("\n[5/6] Testing Unknown Destination MAC Flooding...")
    res_flood = switch_engine.processEthernetFrame(
        switch_id="sw-core",
        ingress_port=1,
        source_mac="AA:BB:CC:01:01:01",
        destination_mac="DE:AD:BE:EF:00:01"  # Unknown MAC
    )
    print(f"    Action: {res_flood.forwarding_action} | Egress Ports Count: {len(res_flood.egress_ports)}")
    assert res_flood.forwarding_action == "FLOOD"
    assert 1 not in res_flood.egress_ports  # Ingress port omitted
    assert 2 in res_flood.egress_ports
    assert 3 in res_flood.egress_ports
    print("    [PASS] Unknown frame flooded out all active ports except ingress port 1.")

    # 6. VLAN Segmentation (Isolate Port 3 into VLAN 10)
    print("\n[6/6] Testing VLAN Segmentation (VLAN 10: Servers, VLAN 20: Clients)...")
    switch_engine.createVlan("sw-core", 10, "Servers", subnet="192.168.10.0/24")
    switch_engine.createVlan("sw-core", 20, "Clients", subnet="192.168.20.0/24")

    switch_engine.assignPortToVlan("sw-core", 1, 20)  # PC1 on VLAN 20
    switch_engine.assignPortToVlan("sw-core", 2, 20)  # PC2 on VLAN 20
    switch_engine.assignPortToVlan("sw-core", 3, 10)  # Server on VLAN 10

    # Broadcast from PC1 in VLAN 20 should reach PC2 (Port 2) but NOT Server (Port 3)
    res_vlan_broadcast = switch_engine.processEthernetFrame(
        switch_id="sw-core",
        ingress_port=1,
        source_mac="AA:BB:CC:01:01:01",
        destination_mac="FF:FF:FF:FF:FF:FF"
    )
    print(f"    VLAN 20 Broadcast Egress Ports: {res_vlan_broadcast.egress_ports}")
    assert 2 in res_vlan_broadcast.egress_ports
    assert 3 not in res_vlan_broadcast.egress_ports  # Isolated!
    print("    [PASS] VLAN 20 broadcast successfully isolated from Server in VLAN 10.")

    print("\n================================================================================")
    print("       ALL 6 SWITCH & LAYER 2 AUDIT TESTS PASSED CLEANLY                        ")
    print("================================================================================")

if __name__ == "__main__":
    run_switch_model_suite()