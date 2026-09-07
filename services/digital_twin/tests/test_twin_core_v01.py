import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.twin_core import DigitalTwinCore
from services.twin_engine.src.core.twin_state import DeviceEntity, DeviceInterface
from packages.shared_types.src.topology import ConnectionEntity
from packages.shared_types.src.device import OperatingSystemProfile, PortEntity, ServiceEntity
from packages.shared_types.src.security import VulnerabilityEntity

def run_twin_core_v01_test():
    print("================================================================================")
    print("       WEEK 4 - DAY 27: DIGITAL TWIN CORE v0.1 COMPONENT HARNESS                ")
    print("================================================================================\n")

    twin = DigitalTwinCore(network_name="CANONICAL-LAB-NET")

    # 1. Instantiate 6 Canonical Devices (DEV-001 through DEV-006)
    print("[1/4] Populating 6-Device Canonical Entities...")

    # DEV-001: PC1
    dev1 = DeviceEntity(
        id="DEV-001",
        hostname="ws-pc-01",
        type="WORKSTATION",
        role="ENGINEERING_CLIENT",
        interfaces=[DeviceInterface(interface_id="eth0", ip_address="192.168.1.11", mac_address="00:50:56:FE:01:11", subnet="192.168.1.0/24")],
        open_ports=[],
        criticality=4.0
    )

    # DEV-002: PC2
    dev2 = DeviceEntity(
        id="DEV-002",
        hostname="ws-pc-02",
        type="WORKSTATION",
        role="FINANCE_CLIENT",
        interfaces=[DeviceInterface(interface_id="eth0", ip_address="192.168.1.12", mac_address="00:50:56:FE:01:12", subnet="192.168.1.0/24")],
        open_ports=[],
        criticality=6.0
    )

    # DEV-003: SERVER
    dev3 = DeviceEntity(
        id="DEV-003",
        hostname="srv-web-01",
        type="SERVER",
        role="APPLICATION_SERVER",
        interfaces=[DeviceInterface(interface_id="eth0", ip_address="192.168.1.10", mac_address="00:50:56:FE:01:10", subnet="192.168.1.0/24")],
        open_ports=[80, 443, 22],
        services=["nginx", "openssh"],
        detailed_ports=[
            PortEntity(port_number=80, protocol="TCP", state="OPEN", bound_service="nginx", is_exposed=True),
            PortEntity(port_number=443, protocol="TCP", state="OPEN", bound_service="nginx", is_exposed=True),
            PortEntity(port_number=22, protocol="TCP", state="OPEN", bound_service="openssh", is_exposed=True)
        ],
        vulnerabilities=[
            VulnerabilityEntity(
                vuln_id="VULN-001",
                cve_id="CVE-2023-38408",
                name="OpenSSH PKCS#11 Forwarding RCE",
                severity="CRITICAL",
                cvss_score=9.8,
                affected_service="openssh",
                port=22,
                status="OPEN"
            )
        ],
        criticality=8.5
    )

    # DEV-004: ROUTER
    dev4 = DeviceEntity(
        id="DEV-004",
        hostname="rtr-gw-01",
        type="ROUTER",
        role="PERIMETER_GATEWAY",
        interfaces=[
            DeviceInterface(interface_id="eth0", ip_address="192.168.1.1", mac_address="00:50:56:FE:01:00", subnet="192.168.1.0/24"),
            DeviceInterface(interface_id="eth1", ip_address="203.0.113.5", mac_address="00:50:56:FE:01:01", subnet="203.0.113.0/30")
        ],
        open_ports=[53, 67],
        services=["dnsmasq", "nat"],
        criticality=9.5
    )

    # DEV-005: SWITCH
    dev5 = DeviceEntity(
        id="DEV-005",
        hostname="sw-core-01",
        type="SWITCH",
        role="CORE_SWITCH",
        interfaces=[DeviceInterface(interface_id="vlan1", ip_address="0.0.0.0", mac_address="00:50:56:FE:01:FE", subnet="192.168.1.0/24")],
        open_ports=[],
        criticality=9.0
    )

    # DEV-006: FIREWALL
    dev6 = DeviceEntity(
        id="DEV-006",
        hostname="fw-edge-01",
        type="FIREWALL",
        role="PERIMETER_INSPECTION",
        interfaces=[
            DeviceInterface(interface_id="eth0", ip_address="192.168.1.254", mac_address="00:50:56:FE:01:EE", subnet="192.168.1.0/24"),
            DeviceInterface(interface_id="eth1", ip_address="203.0.113.2", mac_address="00:50:56:FE:01:EF", subnet="203.0.113.0/30")
        ],
        open_ports=[],
        services=["stateful-dpi", "packet-filter"],
        criticality=9.5
    )

    for d in [dev1, dev2, dev3, dev4, dev5, dev6]:
        twin.register_device(d)
    print(f"    [+] Successfully registered {len(twin.devices.list_devices())} devices into registry.")
    assert len(twin.devices.list_devices()) == 6

    # 2. Establish Topological Relationships
    print("\n[2/4] Linking Devices to Construct Living Topology...")
    twin.register_connection(ConnectionEntity(connection_id="c-pc1-sw", source_device="DEV-001", destination_device="DEV-005", latency_ms=0.4))
    twin.register_connection(ConnectionEntity(connection_id="c-pc2-sw", source_device="DEV-002", destination_device="DEV-005", latency_ms=0.4))
    twin.register_connection(ConnectionEntity(connection_id="c-srv-sw", source_device="DEV-003", destination_device="DEV-005", latency_ms=0.2))
    twin.register_connection(ConnectionEntity(connection_id="c-sw-fw", source_device="DEV-005", destination_device="DEV-006", latency_ms=0.3))
    twin.register_connection(ConnectionEntity(connection_id="c-fw-rtr", source_device="DEV-006", destination_device="DEV-004", latency_ms=0.5))

    print(f"    [+] Topology Links Created: {len(twin.connections.list_connections())}")
    assert len(twin.connections.list_connections()) == 5

    # Test Shortest Path Routing (PC1 to ROUTER across SWITCH and FIREWALL)
    path_res = twin.find_path("DEV-001", "DEV-004")
    print(f"    [+] Transit Path PC1 -> ROUTER: {' -> '.join(path_res.traversed_devices)} ({path_res.hop_count} hops, {path_res.total_latency_ms} ms)")
    assert path_res.hop_count == 3
    assert path_res.path_hops == ["DEV-001", "DEV-005", "DEV-006", "DEV-004"]

    # 3. Dynamic State Machine & Vulnerability Workflow
    print("\n[3/4] Driving Operational Telemetry & State Transitions...")
    twin.update_device_health("DEV-003", cpu_pct=65.0, mem_pct=72.0, pps=320.0, bps=2500000.0)
    
    # Transition to SUSPICIOUS on scan
    twin.transition_security_state("DEV-003", "SUSPICIOUS", "SURICATA_NIDS", "Recon scan probe detected on port 22")
    assert twin.devices.get_device("DEV-003").security_state_model.security_status == "SUSPICIOUS"

    # Patch vulnerability and verify risk update
    print("    [+] Applying vendor remediation patch to CVE-2023-38408...")
    twin.patch_vulnerability("DEV-003", "CVE-2023-38408")
    server_node = twin.devices.get_device("DEV-003")
    assert server_node.vulnerabilities[0].status == "PATCHED"
    print(f"    [+] Updated Risk Score after Patch: {server_node.security_state_model.risk_score}")

    # Transition back to NORMAL
    twin.transition_security_state("DEV-003", "NORMAL", "SOC_ENGINEER", "Service verified nominal after patch")
    assert server_node.security_state_model.security_status == "NORMAL"

    # 4. Render Digital Twin Snapshot
    print("\n[4/4] Generating First Digital Twin System Snapshot:")
    snapshot_output = twin.generate_snapshot_text()
    print(snapshot_output)

    print("\n================================================================================")
    print("       DIGITAL TWIN CORE v0.1 VERIFIED SUCCESSFULLY                             ")
    print("================================================================================")

if __name__ == "__main__":
    run_twin_core_v01_test()