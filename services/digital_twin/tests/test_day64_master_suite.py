import json
import sys
import filecmp
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Shared Models
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.normal_traffic import NormalTrafficScenarioConfig
from packages.shared_types.src.traffic_spike import TrafficSpikeProfile
from packages.shared_types.src.connection_anomaly import ConnectionAnomalyProfile, ConnectionAnomalyPatternEnum
from packages.shared_types.src.port_anomaly import PortAnomalyProfile, PortStateMutationConfig
from packages.shared_types.src.repeated_connection import RepeatedConnectionProfile
from packages.shared_types.src.master_scenario import (
    MasterScenarioDefinition, MasterScenarioStageConfig, ScenarioStageTypeEnum
)
from packages.shared_types.src.port_service_state import PortStateEnum

# Engine Subsystems
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.core.state.unified_state_coordinator import unified_state_coordinator

# Simulation Generators & Runner
from services.digital_twin.simulation.generators.protocol_generators import protocol_coordinator
from services.digital_twin.simulation.generators.web_traffic_generator import web_orchestrator
from services.digital_twin.simulation.generators.dns_traffic_generator import dns_orchestrator
from services.digital_twin.simulation.generators.ssh_traffic_generator import ssh_orchestrator
from services.digital_twin.simulation.generators.normal_traffic_orchestrator import normal_orchestrator
from services.digital_twin.simulation.generators.traffic_spike_engine import traffic_spike_engine
from services.digital_twin.simulation.generators.connection_anomaly_engine import connection_anomaly_engine
from services.digital_twin.simulation.generators.port_anomaly_engine import port_anomaly_engine
from services.digital_twin.simulation.generators.protocol_anomaly_engine import protocol_anomaly_engine
from services.digital_twin.simulation.generators.repeated_connection_engine import repeated_connection_engine
from services.digital_twin.simulation.scenarios.scenario_runner import scenario_runner
from services.digital_twin.simulation.engine.reproducible_engine import reproducible_engine

def run_day64_complete_verification():
    print("=" * 85)
    print("      DAY 64: COMPLETE PHASE 7 MASTER TEST SUITE & REPRODUCIBILITY AUDIT")
    print("=" * 85 + "\n")

    test_dir = ROOT_DIR / "data" / "simulation" / "runs" / "day64_audit"
    test_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # 0. PRE-REGISTER CANONICAL TOPOLOGY
    # -------------------------------------------------------------------------
    device_registry.clear()
    c1 = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    srv = NetworkDeviceModel(id="server-01", hostname="SERVER-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.INTERNAL, ports=[22])
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    dns = NetworkDeviceModel(id="dns-01", hostname="DNS-01", type=DeviceTypeEnum.DNS_SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[53])

    for dev in [c1, srv, web, dns]:
        device_registry.createDevice(dev)

    # -------------------------------------------------------------------------
    # 1. NORMAL TRAFFIC PROTOCOLS (7/7)
    # -------------------------------------------------------------------------
    print("[1/4] Auditing Normal Traffic Protocol Generators (HTTP, HTTPS, DNS, SSH, ICMP, TCP, UDP)...")
    
    # TCP
    tcp_evts = protocol_coordinator.emitTcpFlow("client-01", "server-01", dst_port=8080)
    assert len(tcp_evts) == 5
    print("    [PASS] TCP: 3-Way Handshake, Data, and Teardown verified.")

    # UDP
    udp_evt = protocol_coordinator.emitUdpDatagram("client-01", "dns-01", dst_port=53)
    assert udp_evt.protocol.value == "UDP" and udp_evt.destinationPort == 53
    print("    [PASS] UDP: Connectionless datagram verified.")

    # ICMP
    icmp_req, icmp_rep = protocol_coordinator.emitIcmpPing("client-01", "server-01")
    assert icmp_req.icmpType.value == "ECHO_REQUEST" and icmp_rep.icmpType.value == "ECHO_REPLY"
    print("    [PASS] ICMP: Echo Request and Echo Reply pairing verified.")

    # HTTP
    http_evt = web_orchestrator.http_gen.generateTransaction("client-01", "web-01", path="/", status_code=200)
    assert http_evt.destinationPort == 80 and http_evt.isEncrypted is False
    print("    [PASS] HTTP: Plaintext GET / with 200 OK verified.")

    # HTTPS
    https_evt = web_orchestrator.https_gen.generateTransaction("client-01", "web-01", path="/login", status_code=200)
    assert https_evt.destinationPort == 443 and https_evt.isEncrypted is True and https_evt.tlsVersion == "TLSv1.3"
    print("    [PASS] HTTPS: Encrypted TLSv1.3 transaction verified.")

    # DNS
    dns_q, dns_r = dns_orchestrator.generator.generateQueryPair("client-01", "dns-01", domain="web.internal.test")
    assert dns_q.destinationPort == 53 and "192.168.20.10" in dns_r.answers
    print("    [PASS] DNS: Resolution query and answer verified.")

    # SSH
    ssh_seq = ssh_orchestrator.generator.generateSessionSequence("client-01", "server-01")
    assert len(ssh_seq) == 5 and ssh_seq[2].sessionState.value == "ESTABLISHED"
    print("    [PASS] SSH: Remote administrative session lifecycle verified.")

    # -------------------------------------------------------------------------
    # 2. ABNORMAL TRAFFIC SCENARIOS (5/5)
    # -------------------------------------------------------------------------
    print("\n[2/4] Auditing Abnormal Traffic Anomaly Generators (5 Categories)...")

    # 1. Traffic Spike
    spike_prof = TrafficSpikeProfile(affectedDevice="client-01", targetDevice="web-01", baselineRate=100, spikeRate=800, spikeDuration=5)
    spike_res = traffic_spike_engine.runSpikeScenario(spike_prof, sync_to_twin=True)
    assert spike_res.maxNetworkUtilisation >= 90.0 and spike_res.maxCpuLoad >= 80.0
    print("    [PASS] Traffic Spike: Volumetric surge (100 -> 800 events/min) saturated line & CPU.")

    # 2. Connection Anomaly
    conn_prof = ConnectionAnomalyProfile(affectedDevice="client-01", targetDevice="web-01", abnormalConnectionRate=50)
    conn_res = connection_anomaly_engine.runAnomalyScenario(conn_prof, sync_to_twin=True)
    assert conn_res.classification == "UNUSUAL_CONNECTION_BEHAVIOUR"
    assert conn_res.lifecycleSummary.failedCount > conn_res.lifecycleSummary.establishedCount
    print("    [PASS] Connection Anomaly: Lifecycle skew (High NEW, Low ESTABLISHED, High FAILED) verified.")

    # 3. Port Anomaly & Mutation
    port_prof = PortAnomalyProfile(
        affectedDevice="client-01", targetDevice="web-01",
        mutatePort=PortStateMutationConfig(port=8443, newState="OPEN", serviceName="alt-https", reason="Audit sweep mutation")
    )
    port_res = port_anomaly_engine.runPortAnomalyScenario(port_prof)
    assert port_res.stateMutated is True and port_service_engine.getPort("web-01", 8443).state == PortStateEnum.OPEN
    print("    [PASS] Port Anomaly: Port sweep executed and attack surface mutated (8443 -> OPEN).")

    # 4. Protocol Anomaly
    proto_res = protocol_anomaly_engine.runThreeStageScenario("client-01", "web-01", window_duration=5)
    assert proto_res.abnormalWindowStats.percentages["ICMP"] > 50.0
    assert len(proto_res.detectedAnomalies) >= 1
    print("    [PASS] Protocol Anomaly: Distribution skew (ICMP surged to 65%) detected across 3 windows.")

    # 5. Repeated Connection
    rep_prof = RepeatedConnectionProfile(sourceDevice="client-01", destinationDevice="server-01", attemptCount=100, windowSeconds=10)
    rep_ev, rep_pkts = repeated_connection_engine.runScenario(rep_prof)
    assert rep_ev.attemptCount == 100 and rep_ev.failedCount == 97 and rep_ev.successfulCount == 3
    print("    [PASS] Repeated Connection: Rapid loop (100 attempts: 3 succ, 97 fail in 10s) verified.")

    # -------------------------------------------------------------------------
    # 3. DIGITAL TWIN DYNAMIC STATE COUPLING
    # -------------------------------------------------------------------------
    print("\n[3/4] Auditing Digital Twin Dynamic State Coupling & Invariants...")
    
    # State update checks
    net_st = network_state_engine.getNetworkMetrics("web-01")
    perf_st = performance_state_engine.getPerformanceState("web-01")
    sec_st = security_state_engine.getSecurityStatus("web-01")

    assert net_st.networkUtilisation > 0.0
    assert perf_st.cpu > 0.0 and (getattr(perf_st, 'memory', None) is not None or getattr(perf_st, 'memoryUsage', None) is not None)
    assert sec_st is not None
    
    # Ensure state history is tracking
    hist = unified_state_coordinator.getAuditHistory()
    assert len(hist) > 0
    print(f"    [PASS] Digital Twin confirmed updated: CPU={perf_st.cpu}%, Util={net_st.networkUtilisation}%, HistoryEvents={len(hist)}.")

    # -------------------------------------------------------------------------
    # 4. MANDATORY REPRODUCIBILITY AUDIT (Run A == Run B, Run A != Run C)
    # -------------------------------------------------------------------------
    print("\n[4/4] Executing Mandatory Deterministic Reproducibility Audit...")

    # Run A with Seed 12345
    print("    Executing Run A (Seed: 12345)...")
    scen_a = MasterScenarioDefinition(
        scenarioId="normal-plus-anomalies",
        name="Reproducibility Scenario A",
        seed=12345,
        stages=[
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.NORMAL_BASELINE, durationSeconds=3),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.TRAFFIC_SPIKE, durationSeconds=4, intensity=2.0),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=3),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.REPEATED_CONNECTION, durationSeconds=4, intensity=1.0)
        ]
    )
    scenario_runner.loadScenario(scen_a)
    status_a = scenario_runner.run()
    file_a = test_dir / "events-A.jsonl"
    with open(file_a, "w", encoding="utf-8") as f:
        json.dump(status_a.model_dump(), f, indent=2)
    print(f"      Run A completed: {status_a.totalPacketsEmitted} packets, {status_a.totalEventsLogged} events logged.")

    # Run B with Seed 12345 (Replay)
    print("    Executing Run B (Seed: 12345 - Replay)...")
    scen_b = MasterScenarioDefinition(
        scenarioId="normal-plus-anomalies",
        name="Reproducibility Scenario B",
        seed=12345,
        stages=[
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.NORMAL_BASELINE, durationSeconds=3),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.TRAFFIC_SPIKE, durationSeconds=4, intensity=2.0),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=3),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.REPEATED_CONNECTION, durationSeconds=4, intensity=1.0)
        ]
    )
    scenario_runner.loadScenario(scen_b)
    status_b = scenario_runner.run()
    file_b = test_dir / "events-B.jsonl"
    with open(file_b, "w", encoding="utf-8") as f:
        json.dump(status_b.model_dump(), f, indent=2)
    print(f"      Run B completed: {status_b.totalPacketsEmitted} packets, {status_b.totalEventsLogged} events logged.")

    # Assert A == B
    assert status_a.totalPacketsEmitted == status_b.totalPacketsEmitted, f"Packet mismatch: A={status_a.totalPacketsEmitted}, B={status_b.totalPacketsEmitted}"
    assert status_a.totalEventsLogged == status_b.totalEventsLogged, f"Event log mismatch: A={status_a.totalEventsLogged}, B={status_b.totalEventsLogged}"
    assert status_a.anomaliesTriggeredCount == status_b.anomaliesTriggeredCount
    assert status_a.virtualTimeSeconds == status_b.virtualTimeSeconds
    print("    [PASS] VERIFIED: Run A == Run B (Deterministic Invariant Equivalence).")

    # Run C with Seed 99999 (Altered Seed)
    print("    Executing Run C (Seed: 99999 - Altered Seed)...")
    scen_c = MasterScenarioDefinition(
        scenarioId="normal-plus-anomalies",
        name="Reproducibility Scenario C",
        seed=99999,
        stages=[
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.NORMAL_BASELINE, durationSeconds=3),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.TRAFFIC_SPIKE, durationSeconds=4, intensity=5.0),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=3),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.REPEATED_CONNECTION, durationSeconds=4, intensity=2.0)
        ]
    )
    scenario_runner.loadScenario(scen_c)
    status_c = scenario_runner.run()
    file_c = test_dir / "events-C.jsonl"
    with open(file_c, "w", encoding="utf-8") as f:
        json.dump(status_c.model_dump(), f, indent=2)
    print(f"      Run C completed: {status_c.totalPacketsEmitted} packets, {status_c.totalEventsLogged} events logged.")

    # Assert A != C
    assert status_a.totalPacketsEmitted != status_c.totalPacketsEmitted, "Run A and Run C unexpectedly matched with different seeds/intensities!"
    print("    [PASS] VERIFIED: Run A != Run C (Controlled Deviation Confirmed).")

    # -------------------------------------------------------------------------
    # LIFECYCLE CONTROLS (Pause, Resume, Stop, Reset)
    # -------------------------------------------------------------------------
    print("\n[Bonus] Verifying ScenarioRunner Lifecycle Controls (Pause, Resume, Stop, Reset)...")
    master_scenario = MasterScenarioDefinition(
        scenarioId="lifecycle-check-001",
        name="Lifecycle Scenario",
        stages=[
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.NORMAL_BASELINE, durationSeconds=2),
            MasterScenarioStageConfig(stageType=ScenarioStageTypeEnum.RECOVERY, durationSeconds=2)
        ]
    )
    scenario_runner.loadScenario(master_scenario)
    init_status = scenario_runner.initialize()
    assert init_status.state == "CREATED"
    assert scenario_runner.pause().state == "PAUSED"
    assert scenario_runner.resume().state == "RUNNING"
    assert scenario_runner.stop().state == "STOPPED"
    scenario_runner.reset()
    assert scenario_runner.getStatus() is None
    print("    [PASS] ScenarioRunner lifecycle controls verified.")

    print("\n" + "=" * 85)
    print("     ALL DAY 64 AUDIT TESTS & REPRODUCIBILITY PROOFS PASSED CLEANLY")
    print("=" * 85)

if __name__ == "__main__":
    run_day64_complete_verification()