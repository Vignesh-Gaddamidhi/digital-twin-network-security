import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.topology import NetworkConnectionModel

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.connections.network_connection_registry import connection_registry
from services.digital_twin.core.topology.graph_engine import graph_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine

from services.digital_twin.simulation.attack.scenarios.port_discovery_scenario import PortDiscoveryScenario
from services.digital_twin.simulation.attack.scenarios.brute_force_scenario import BruteForceAttackScenario
from services.digital_twin.simulation.attack.scenarios.dos_saturation_scenario import DosSaturationScenario
from services.digital_twin.simulation.attack.scenarios.suspicious_dns_scenario import SuspiciousDnsScenario
from services.digital_twin.simulation.attack.scenarios.beaconing_scenario import BeaconingAttackScenario
from services.digital_twin.simulation.attack.scenarios.lateral_movement_scenario import LateralMovementScenario
from services.digital_twin.simulation.attack.scenarios.data_exfiltration_scenario import DataExfiltrationScenario

def provision_environment():
    device_registry.clear()
    connection_registry.clear()
    graph_engine.clear()
    port_service_engine.clear()
    network_state_engine.clear()
    performance_state_engine.clear()

    cli = NetworkDeviceModel(id="CLIENT-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    srv = NetworkDeviceModel(id="SERVER-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22, 443])
    web = NetworkDeviceModel(id="WEB-01",    hostname="WEB-01",    type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    dns = NetworkDeviceModel(id="DNS-01",    hostname="DNS-01",    type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])
    s2  = NetworkDeviceModel(id="SERVER-02", hostname="SERVER-02", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[445])
    db  = NetworkDeviceModel(id="DB-01",     hostname="DB-01",     type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])
    ext = NetworkDeviceModel(id="EXTERNAL-SIMULATED-ENDPOINT", hostname="EXT-C2", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.EXTERNAL, ports=[443])

    for d in [cli, srv, web, dns, s2, db, ext]:
        device_registry.createDevice(d)
        graph_engine.addNode(d)

    # Topology links
    for idx, (s, dst) in enumerate([
        ("CLIENT-01", "SERVER-01"), ("CLIENT-01", "WEB-01"), ("CLIENT-01", "DNS-01"),
        ("SERVER-01", "SERVER-02"), ("SERVER-02", "DB-01"),  ("CLIENT-01", "EXTERNAL-SIMULATED-ENDPOINT")
    ]):
        c = NetworkConnectionModel(id=f"conn-{idx}", sourceDevice=s, destinationDevice=dst)
        connection_registry.createConnection(c)
        graph_engine.addEdge(c, is_bidirectional=True)

    port_service_engine.openPort("SERVER-01", 22, protocol="TCP", service_name="SSH")
    port_service_engine.openPort("SERVER-01", 443, protocol="TCP", service_name="HTTPS")
    port_service_engine.openPort("WEB-01", 443, protocol="TCP", service_name="HTTPS")
    port_service_engine.openPort("DNS-01", 53, protocol="UDP", service_name="DNS")
    port_service_engine.openPort("SERVER-02", 445, protocol="TCP", service_name="SMB")
    port_service_engine.openPort("DB-01", 5432, protocol="TCP", service_name="POSTGRESQL")
    port_service_engine.openPort("EXTERNAL-SIMULATED-ENDPOINT", 443, protocol="TCP", service_name="HTTPS")

def run_graduation_suite():
    print("=" * 80)
    print("       PHASE 8 GRAND GRADUATION & COMPLETE CANONICAL MATRIX AUDIT")
    print("=" * 80 + "\n")

    # 1. Deterministic Reproducibility Audit (Invariant: A == A, A != B)
    print("[1/3] Auditing Deterministic Reproducibility on SCN-BEACON-001...")
    provision_environment()

    scen_a1 = BeaconingAttackScenario(source_device="CLIENT-01", target_device="SERVER-01", seed=12345)
    evts_a1 = [(e.sourcePort, e.timestamp, e.bytes) for e in scen_a1.generate_traffic_events()]

    scen_a2 = BeaconingAttackScenario(source_device="CLIENT-01", target_device="SERVER-01", seed=12345)
    evts_a2 = [(e.sourcePort, e.timestamp, e.bytes) for e in scen_a2.generate_traffic_events()]

    scen_b = BeaconingAttackScenario(source_device="CLIENT-01", target_device="SERVER-01", seed=67890)
    evts_b = [(e.sourcePort, e.timestamp, e.bytes) for e in scen_b.generate_traffic_events()]

    assert evts_a1 == evts_a2, "Determinism Failure: Identical seed produced divergent packet sequences"
    assert evts_a1 != evts_b,  "Deviation Failure: Different seed produced identical packet sequences"
    print("    [PASS] Invariant Verified: Seed 12345 (A == A), Seed 67890 (A != B).")

    # 2. Complete 7-Scenario Canonical Matrix Execution Audit
    print("\n[2/3] Executing All 7 Canonical Attack Scenarios Through End-to-End Lifecycle...")
    canonical_matrix = [
        ("SCN-PORTSCAN-001",   PortDiscoveryScenario("CLIENT-01", "SERVER-01", seed=12345), "MEDIUM"),
        ("SCN-BRUTEFORCE-001", BruteForceAttackScenario("CLIENT-01", "SERVER-01", seed=12345), "HIGH"),
        ("SCN-DOS-001",        DosSaturationScenario("CLIENT-01", "WEB-01", seed=12345), "HIGH"),
        ("SCN-DNS-001",        SuspiciousDnsScenario("CLIENT-01", "DNS-01", seed=12345), "MEDIUM"),
        ("SCN-BEACON-001",     BeaconingAttackScenario("CLIENT-01", "SERVER-01", seed=12345), "HIGH"),
        ("SCN-LATERAL-001",    LateralMovementScenario("CLIENT-01", "SERVER-01", "SERVER-02", "DB-01", seed=12345), "HIGH"),
        ("SCN-EXFIL-001",      DataExfiltrationScenario("CLIENT-01", "EXTERNAL-SIMULATED-ENDPOINT", seed=12345), "CRITICAL"),
    ]

    for scn_id, scn_inst, expected_sev in canonical_matrix:
        provision_environment()
        res = scn_inst.execute()
        print(f"    {scn_id:<20} -> Status: {res.finalState:<10} | Severity: {res.riskLevel:<8} | Indicators: {len(res.indicatorsObserved)} | Healed: {res.recoveryVerified}")
        assert res.finalState == "COMPLETED"
        assert res.riskLevel == expected_sev
        assert len(res.indicatorsObserved) >= 3
        assert res.recoveryVerified is True
    print("    [PASS] All 7 canonical scenarios executed, detected, scored, and healed to baseline.")

    # 3. Verify Final Digital Twin Baseline Cleanliness
    print("\n[3/3] Auditing Clean Post-Execution Digital Twin Posture...")
    for dev_id in ["CLIENT-01", "SERVER-01", "WEB-01", "DNS-01", "SERVER-02", "DB-01"]:
        conns = network_state_engine.getConnectionStats(dev_id).active
        cpu = performance_state_engine.getPerformanceState(dev_id).cpu
        util = network_state_engine.getNetworkMetrics(dev_id).networkUtilisation
        assert conns == 0
        assert cpu <= 25.0
        assert util <= 20.0
    print("    [PASS] All virtual hosts confirmed operating at normal baseline telemetry.")

    print("\n" + "=" * 80)
    print("       PHASE 8 GRADUATION AUDIT: 100% SUCCESS — READY FOR PHASE 9")
    print("=" * 80)

if __name__ == "__main__":
    run_graduation_suite()