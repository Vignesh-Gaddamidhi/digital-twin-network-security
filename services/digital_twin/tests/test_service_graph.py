import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.service_graph import (
    DetailedServiceDependencyModel, ServiceCriticalityEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.topology.service_graph_engine import service_graph_engine

def run_service_graph_suite():
    print("================================================================================")
    print("       WEEK 6 - DAY 40: SERVICE GRAPH & IMPACT PROPAGATION AUDIT                ")
    print("================================================================================\n")

    device_registry.clear()
    service_graph_engine.clear()

    # 1. Provision Canonical Devices
    print("[1/4] Provisioning Endpoints (Client, Web Server, Database, DNS)...")
    client = NetworkDeviceModel(id="client-01", hostname="client-01", type=DeviceTypeEnum.CLIENT)
    web = NetworkDeviceModel(id="web-01", hostname="web-01", type=DeviceTypeEnum.SERVER, ports=[80, 443])
    db = NetworkDeviceModel(id="db-01", hostname="db-01", type=DeviceTypeEnum.DATABASE, ports=[5432])
    dns = NetworkDeviceModel(id="dns-01", hostname="dns-01", type=DeviceTypeEnum.DNS_SERVER, ports=[53])

    for d in [client, web, db, dns]:
        device_registry.createDevice(d)

    print("    [PASS] 4 devices registered.")

    # 2. Wire Service Dependencies
    print("\n[2/4] Registering Detailed Service Dependencies...")
    
    # Client -> Web App (TCP 443)
    service_graph_engine.addDependency(DetailedServiceDependencyModel(
        id="dep-cli-web",
        sourceDevice="client-01",
        sourceService="browser",
        destinationDevice="web-01",
        destinationService="web-app",
        protocol="TCP",
        port=443,
        criticality=ServiceCriticalityEnum.CRITICAL
    ))

    # Web App -> PostgreSQL (TCP 5432)
    service_graph_engine.addDependency(DetailedServiceDependencyModel(
        id="dep-web-db",
        sourceDevice="web-01",
        sourceService="web-app",
        destinationDevice="db-01",
        destinationService="postgresql",
        protocol="TCP",
        port=5432,
        criticality=ServiceCriticalityEnum.HIGH
    ))

    # Client -> DNS (UDP 53)
    service_graph_engine.addDependency(DetailedServiceDependencyModel(
        id="dep-cli-dns",
        sourceDevice="client-01",
        sourceService="os-resolver",
        destinationDevice="dns-01",
        destinationService="dnsmasq",
        protocol="UDP",
        port=53,
        criticality=ServiceCriticalityEnum.HIGH
    ))

    deps = service_graph_engine.listDependencies()
    assert len(deps) == 3
    print(f"    [PASS] 3 service dependencies registered in graph.")

    # 3. Test Upstream Impact Propagation on Database Failure
    print("\n[3/4] Simulating Database Server Failure (db-01:postgresql) & Propagating Impact...")
    impact = service_graph_engine.propagateImpact("db-01", "postgresql")
    
    print(f"    Failed Component         : {impact.failed_device_id}::{impact.failed_service}")
    print(f"    Total Impacted Services  : {impact.total_impacted_services}")
    print(f"    Total Impacted Devices   : {impact.total_impacted_devices}")
    print(f"    Blast Radius Score       : {impact.blast_radius_score}")
    print("    Cascade Flow Details:")
    for imp in impact.impacted_services:
        print(f"      - Depth {imp.dependency_depth}: [{imp.device_id}] {imp.service_name} (Direct: {imp.direct_dependency})")

    # Assertions
    assert impact.total_impacted_services == 2
    assert impact.total_impacted_devices == 2

    # web-app is direct consumer (depth 1)
    web_impact = next(s for s in impact.impacted_services if s.device_id == "web-01")
    assert web_impact.direct_dependency is True
    assert web_impact.dependency_depth == 1

    # client-01 is transitive consumer (depth 2)
    client_impact = next(s for s in impact.impacted_services if s.device_id == "client-01")
    assert client_impact.direct_dependency is False
    assert client_impact.dependency_depth == 2

    # DNS must be unaffected
    assert not any(s.device_id == "dns-01" for s in impact.impacted_services)

    print("    [PASS] Upstream blast radius accurately isolated: DB -> Web App -> Client.")

    # 4. Error Handling: Non-Existent Service Target
    print("\n[4/4] Testing Isolation of Independent Services (dns-01:dnsmasq)...")
    dns_impact = service_graph_engine.propagateImpact("dns-01", "dnsmasq")
    assert dns_impact.total_impacted_devices == 1  # Only client-01
    assert dns_impact.impacted_services[0].device_id == "client-01"
    print("    [PASS] Independent branch propagation confirmed.")

    print("\n================================================================================")
    print("       ALL SERVICE GRAPH & IMPACT PROPAGATION TESTS PASSED CLEANLY              ")
    print("================================================================================")

if __name__ == "__main__":
    run_service_graph_suite()