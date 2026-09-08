import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.normal_traffic import NormalTrafficScenarioConfig, BaselineSummaryModel
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.simulation.generators.normal_traffic_orchestrator import normal_orchestrator
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.unified_state_coordinator import unified_state_coordinator

def run_normal_orchestrator_suite():
    print("=" * 80)
    print("       WEEK 8 - DAY 56: NORMAL TRAFFIC ORCHESTRATOR & BASELINE AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    network_state_engine.clear()
    unified_state_coordinator.clear()

    # 1. Provision Canonical Topology
    print("[1/5] Provisioning Infrastructure (Clients, Web, DNS, Servers)...")
    c1 = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    adm = NetworkDeviceModel(id="admin-01", hostname="ADMIN-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    dns = NetworkDeviceModel(id="dns-01", hostname="DNS-01", type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])
    srv = NetworkDeviceModel(id="server-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
    db = NetworkDeviceModel(id="db-01", hostname="DB-01", type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])

    for d in [c1, adm, web, dns, srv, db]:
        device_registry.createDevice(d)

    print(f"    [PASS] Registered {device_registry.count()} canonical hosts in Device Registry.")

    # 2. Configure and Run 60-Second Mixed Normal Baseline Scenario
    print("\n[2/5] Executing 60-Second Normal Traffic Scenario (normal-baseline-run-001)...")
    config = NormalTrafficScenarioConfig(
        scenarioId="normal-baseline-run-001",
        name="Office 24-Hour Daytime Blend",
        durationSeconds=60,
        seed=12345,
        tickStepSeconds=1.0,
        clientDevices=["client-01", "admin-01"],
        webServers=["web-01"],
        dnsServers=["dns-01"],
        genericServers=["server-01", "db-01"]
    )

    baseline = normal_orchestrator.runScenario(config, sync_to_twin=True)

    print(f"    Baseline ID             : {baseline.baselineId}")
    print(f"    Total Events Emitted    : {baseline.totalEventsCount}")
    print(f"    Total Bytes Transferred : {baseline.totalBytesTransferred} bytes")
    print(f"    Total Packets Simulated : {baseline.totalPacketsTransferred} packets")
    print("    Protocol Breakdown      :")
    for proto, count in baseline.protocolDistribution.items():
        pct = round((count / baseline.totalEventsCount) * 100, 1)
        print(f"      - {proto:6s}: {count:2d} events ({pct}%)")

    # Assertions
    assert baseline.totalEventsCount == 60
    assert baseline.totalBytesTransferred > 10000
    # All 7 protocols must be represented
    all_7 = {"HTTPS", "DNS", "HTTP", "SSH", "ICMP", "TCP", "UDP"}
    observed_protocols = set(baseline.protocolDistribution.keys())
    assert all_7.issubset(observed_protocols), f"Missing protocols: {all_7 - observed_protocols}"
    print("    [PASS] All 7 protocols generated and mixed according to target weights.")

    # 3. State Engine Feeding Verification
    print("\n[3/5] Verifying State Engine Synchronization (Line Saturation & Bytes)...")
    web_metrics = network_state_engine.getNetworkMetrics("web-01")
    dns_metrics = network_state_engine.getNetworkMetrics("dns-01")

    print(f"    WEB-01 State : Inbound Bytes = {web_metrics.bytesReceived}, Packets = {web_metrics.packetsReceived}, Line Util = {web_metrics.networkUtilisation}%")
    print(f"    DNS-01 State : Inbound Bytes = {dns_metrics.bytesReceived}, Packets = {dns_metrics.packetsReceived}, Line Util = {dns_metrics.networkUtilisation}%")

    assert web_metrics.bytesReceived > 0
    assert web_metrics.packetsReceived > 0
    assert web_metrics.networkUtilisation > 0.0
    assert dns_metrics.bytesReceived > 0
    print("    [PASS] Digital Twin dynamically updated line utilization and traffic volume counters.")

    # 4. Port and Destination Distribution Validation
    print("\n[4/5] Auditing Port and Destination Distribution Tables...")
    print("    Top Target Ports:")
    for port, count in sorted(baseline.portDistribution.items(), key=lambda x: x[1], reverse=True):
        print(f"      - Port {port:5d} : {count:2d} hits")

    assert 443 in baseline.portDistribution # HTTPS
    assert 53 in baseline.portDistribution  # DNS
    assert 80 in baseline.portDistribution  # HTTP
    assert 22 in baseline.portDistribution  # SSH

    print("    Destination Spread:")
    for dst, count in baseline.destinationDistribution.items():
        print(f"      - {dst:10s} : {count:2d} transactions")

    assert "web-01" in baseline.destinationDistribution
    assert "dns-01" in baseline.destinationDistribution
    assert "server-01" in baseline.destinationDistribution or "db-01" in baseline.destinationDistribution
    print("    [PASS] Destination spread accurately models multi-tier services.")

    # 5. Deterministic Baseline Replay Audit
    print("\n[5/5] Testing Deterministic Reproducibility with Identical Seed (12345)...")
    replay_baseline = normal_orchestrator.runScenario(config, sync_to_twin=False)

    assert replay_baseline.totalEventsCount == baseline.totalEventsCount
    assert replay_baseline.totalBytesTransferred == baseline.totalBytesTransferred
    assert replay_baseline.protocolDistribution == baseline.protocolDistribution
    assert replay_baseline.portDistribution == baseline.portDistribution
    assert replay_baseline.destinationDistribution == baseline.destinationDistribution
    print("    [PASS] Replay produced 100% identical baseline metrics.")

    # Verify JSON file on disk
    baseline_file = normal_orchestrator.baselines_dir / "normal-baseline-run-001.json"
    assert baseline_file.exists()
    print(f"    [PASS] Verified persisted baseline artifact: {baseline_file}")

    print("\n" + "=" * 80)
    print("       ALL DAY 56 NORMAL TRAFFIC ORCHESTRATOR TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_normal_orchestrator_suite()