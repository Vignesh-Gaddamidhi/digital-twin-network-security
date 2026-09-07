import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import (
    NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum, NetworkInterfaceConfig
)
from packages.shared_types.src.service_dependency import (
    ServiceDependencyModel, DependencyTypeEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.topology.service_dependency_engine import service_dependency_engine

def run_service_dependency_suite():
    print("================================================================================")
    print("       WEEK 5 - DAY 34: SERVERS, CLIENTS & SERVICE DEPENDENCY AUDIT             ")
    print("================================================================================\n")

    device_registry.clear()
    service_dependency_engine.clear()

    # 1. Provision Canonical Endpoints
    print("[1/5] Provisioning Canonical Servers and Clients...")

    web_server = NetworkDeviceModel(
        id="web-server-01",
        hostname="WEB-SERVER-01",
        type=DeviceTypeEnum.SERVER,
        role="WEB_SERVER",
        ipAddresses=["192.168.20.10"],
        interfaces=[NetworkInterfaceConfig(interface_id="eth0", ip_address="192.168.20.10", mac_address="AA:BB:CC:20:00:10", subnet_cidr="192.168.20.0/24")],
        operatingSystem="Ubuntu Linux",
        services=["HTTP", "HTTPS"],
        ports=[80, 443],
        networkZone=NetworkZoneEnum.DMZ
    )

    db_server = NetworkDeviceModel(
        id="db-server-01",
        hostname="DB-SERVER-01",
        type=DeviceTypeEnum.DATABASE,
        role="DATABASE_SERVER",
        ipAddresses=["192.168.20.20"],
        interfaces=[NetworkInterfaceConfig(interface_id="eth0", ip_address="192.168.20.20", mac_address="AA:BB:CC:20:00:20", subnet_cidr="192.168.20.0/24")],
        operatingSystem="Ubuntu Linux",
        services=["PostgreSQL"],
        ports=[5432],
        networkZone=NetworkZoneEnum.INTERNAL
    )

    dns_server = NetworkDeviceModel(
        id="dns-server-01",
        hostname="DNS-SERVER-01",
        type=DeviceTypeEnum.DNS_SERVER,
        role="DNS_SERVER",
        ipAddresses=["192.168.20.30"],
        interfaces=[NetworkInterfaceConfig(interface_id="eth0", ip_address="192.168.20.30", mac_address="AA:BB:CC:20:00:30", subnet_cidr="192.168.20.0/24")],
        operatingSystem="Linux",
        services=["DNS"],
        ports=[53],
        networkZone=NetworkZoneEnum.INTERNAL
    )

    client = NetworkDeviceModel(
        id="client-01",
        hostname="CLIENT-01",
        type=DeviceTypeEnum.CLIENT,
        role="WORKSTATION",
        ipAddresses=["192.168.30.10"],
        interfaces=[NetworkInterfaceConfig(interface_id="eth0", ip_address="192.168.30.10", mac_address="AA:BB:CC:30:00:10", subnet_cidr="192.168.30.0/24")],
        operatingSystem="Windows 11 Enterprise",
        networkZone=NetworkZoneEnum.INTERNAL
    )

    for d in [web_server, db_server, dns_server, client]:
        device_registry.createDevice(d)
        print(f"    [+] Created: {d.hostname:14s} | IP: {d.ipAddresses[0]:14s} | Role: {d.role:15s} | Ports: {d.ports}")

    assert device_registry.count() == 4

    # 2. Establish Service Relationships
    print("\n[2/5] Registering Service Dependencies...")

    # Client -> Web Server (TCP 443)
    dep1 = service_dependency_engine.registerDependency(ServiceDependencyModel(
        id="dep-client-web",
        source_device_id="client-01",
        target_device_id="web-server-01",
        target_service_name="HTTPS",
        target_port=443,
        protocol="TCP",
        dependency_type=DependencyTypeEnum.UPSTREAM_CLIENT
    ))
    print(f"    [PASS] Registered: CLIENT-01 -> WEB-SERVER-01 (TCP 443)")

    # Web Server -> Database Server (TCP 5432)
    dep2 = service_dependency_engine.registerDependency(ServiceDependencyModel(
        id="dep-web-db",
        source_device_id="web-server-01",
        target_device_id="db-server-01",
        target_service_name="PostgreSQL",
        target_port=5432,
        protocol="TCP",
        dependency_type=DependencyTypeEnum.BACKEND_DATASTORE
    ))
    print(f"    [PASS] Registered: WEB-SERVER-01 -> DB-SERVER-01 (TCP 5432)")

    # Client -> DNS Server (UDP 53)
    dep3 = service_dependency_engine.registerDependency(ServiceDependencyModel(
        id="dep-client-dns",
        source_device_id="client-01",
        target_device_id="dns-server-01",
        target_service_name="DNS",
        target_port=53,
        protocol="UDP",
        dependency_type=DependencyTypeEnum.INFRASTRUCTURE_CORE
    ))
    print(f"    [PASS] Registered: CLIENT-01 -> DNS-SERVER-01 (UDP 53)")

    assert len(service_dependency_engine.listAllDependencies()) == 3

    # 3. Direct Dependency Tracing
    print("\n[3/5] Testing Direct Dependency: CLIENT-01 -> WEB-SERVER-01...")
    chain_direct = service_dependency_engine.traceDependencyChain("client-01", "web-server-01")
    print(f"    Chain : {' -> '.join(chain_direct.dependency_chain)}")
    print(f"    Direct: {chain_direct.direct_dependency} | Depth: {chain_direct.total_depth}")
    assert chain_direct.direct_dependency is True
    assert chain_direct.total_depth == 1
    assert chain_direct.dependency_chain == ["CLIENT-01", "WEB-SERVER-01"]

    # 4. Transitive Multi-Tier Dependency Tracing
    print("\n[4/5] Testing Transitive Dependency: CLIENT-01 -> DB-SERVER-01 (via Web Tier)...")
    chain_transitive = service_dependency_engine.traceDependencyChain("client-01", "db-server-01")
    print(f"    Chain : {' -> '.join(chain_transitive.dependency_chain)}")
    print(f"    Direct: {chain_transitive.direct_dependency} | Depth: {chain_transitive.total_depth}")
    print(f"    Detail: {chain_transitive.explanation}")
    assert chain_transitive.direct_dependency is False
    assert chain_transitive.total_depth == 2
    assert chain_transitive.dependency_chain == ["CLIENT-01", "WEB-SERVER-01", "DB-SERVER-01"]

    # 5. Rejection: Non-Listening Port Target
    print("\n[5/5] Testing Rejection of Dependency on Closed/Unconfigured Port...")
    try:
        service_dependency_engine.registerDependency(ServiceDependencyModel(
            source_device_id="client-01",
            target_device_id="db-server-01",
            target_service_name="RDP",
            target_port=3389  # Not open on DB server
        ))
        assert False, "Failed to reject dependency on non-listening port!"
    except ValueError as e:
        print(f"    [PASS] Safely rejected invalid dependency: {e}")

    print("\n================================================================================")
    print("       ALL 5 SERVICE DEPENDENCY AUDIT TESTS PASSED CLEANLY                      ")
    print("================================================================================")

if __name__ == "__main__":
    run_service_dependency_suite()