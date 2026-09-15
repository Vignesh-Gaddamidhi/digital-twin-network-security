import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from frontend.topology.topology_models import TopologyNodeState
from frontend.dashboard.device_inspection_models import EpistemicProvenanceEnum
from frontend.dashboard.device_inspection_engine import device_inspection_engine
from frontend.topology.security_3d_renderer_engine import security_3d_renderer_engine

def run_day159_suite():
    print("=" * 80)
    print("       WEEK 23 - DAY 159: 3D SECURITY STATE & RISK VISUALIZATION AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 1. 7 Canonical Security States Mapping
    print("[1/8] Auditing Canonical Security States to 3D Shader Properties...")
    states_to_test = [
        (TopologyNodeState.NORMAL, "#10B981", 0.0, False),
        (TopologyNodeState.MONITORED, "#06B6D4", 1.0, False),
        (TopologyNodeState.SUSPICIOUS, "#F59E0B", 1.8, False),
        (TopologyNodeState.AT_RISK, "#F97316", 2.5, False),
        (TopologyNodeState.COMPROMISED, "#EF4444", 4.0, False),
        (TopologyNodeState.ISOLATED, "#64748B", 0.0, True),
        (TopologyNodeState.UNKNOWN, "#94A3B8", 0.5, False)
    ]
    for st, expected_color, expected_pulse, expected_cage in states_to_test:
        cfg = security_3d_renderer_engine.STATE_HALO_CONFIG[st]
        print(f"    State: {st.value:<12} -> Color: {cfg['color']:<8} | Pulse: {cfg['pulse']}Hz | Cage: {cfg['cage']}")
        assert cfg["color"] == expected_color
        assert cfg["pulse"] == expected_pulse
        assert cfg["cage"] == expected_cage
    print("    [PASS] All 7 canonical security states mapped to distinct 3D visual properties.")

    # 2. Baseline Security Snapshot
    print("\n[2/8] Auditing 3D Security Snapshot Generation...")
    snap = security_3d_renderer_engine.get_snapshot()
    print(f"    Total Devices : {snap.totalDevices} | Compromised: {snap.compromisedCount} | Beacons: {snap.activeBeaconsCount}")
    assert snap.totalDevices >= 5
    assert "WEB-01" in snap.securityVisuals
    print("    [PASS] 3D security snapshot assembled.")

    # 3. Compromised-State Visualization (WEB-01 set to COMPROMISED)
    print("\n[3/8] Auditing COMPROMISED State Shader & Threat Beacon (WEB-01)...")
    attack_path_graph.get_node("WEB-01").securityState = "COMPROMISED"
    web_vis = security_3d_renderer_engine.get_device_security_visual("WEB-01")

    print(f"    WEB-01 Security State : {web_vis.securityState.value}")
    print(f"    Halo Color Hex        : {web_vis.haloColorHex}")
    print(f"    Pulse Frequency       : {web_vis.pulseFrequencyHz} Hz")
    print(f"    Threat Beacon Active  : {web_vis.hasThreatBeacon}")
    print(f"    Beacon Event Type     : {web_vis.activeBeacon.eventType}")

    assert web_vis.securityState == TopologyNodeState.COMPROMISED
    assert web_vis.haloColorHex == "#EF4444"
    assert web_vis.pulseFrequencyHz == 4.0
    assert web_vis.hasThreatBeacon is True
    print("    [PASS] Compromised visual indicators and active beacon verified.")

    # 4. Isolated-State Visualization (CLIENT-01 set to ISOLATED)
    print("\n[4/8] Auditing ISOLATED State & Hexagonal Wireframe Cage (CLIENT-01)...")
    twin_graph_synchronizer.isolate_device("CLIENT-01")
    client_vis = security_3d_renderer_engine.get_device_security_visual("CLIENT-01")

    print(f"    CLIENT-01 State       : {client_vis.securityState.value}")
    print(f"    Halo Color Hex        : {client_vis.haloColorHex}")
    print(f"    Emissive Intensity    : {client_vis.emissiveIntensity}")
    print(f"    Isolation Cage Active : {client_vis.hasIsolationCage}")

    assert client_vis.securityState == TopologyNodeState.ISOLATED
    assert client_vis.hasIsolationCage is True
    assert client_vis.emissiveIntensity == 0.0
    print("    [PASS] Isolated host encapsulated with zero emissive wireframe cage.")

    # 5. Risk Indicators & Formula Tooltip
    print("\n[5/8] Auditing Risk Factor Tooltip Breakdown (DB-01)...")
    db_vis = security_3d_renderer_engine.get_device_security_visual("DB-01")
    r = db_vis.risk
    print(f"    DB-01 Score : {r.riskScore:.1f} [{r.riskLevel.value}]")
    print(f"    Factors     : P={r.threatProbability} | C={r.assetCriticality} | V={r.vulnerabilityFactor} | I={r.attackImpact}")
    print(f"    Formula     : {r.formulaString}")

    assert r.riskScore >= 60.0
    assert r.assetCriticality in ("HIGH", "CRITICAL")
    assert r.formulaString == "P(threat) × C(asset) × V(vuln) × I(impact)"
    print("    [PASS] Contextual risk factors and formula tooltip verified.")

    # 6. Vulnerability Badging
    print("\n[6/8] Auditing Vulnerability Badging on Exposed Devices...")
    attack_path_graph.get_node("WEB-01").vulnerabilities = ["CVE-2026-WEB-RCE"]
    web_vulns = security_3d_renderer_engine.get_device_security_visual("WEB-01").vulnerabilities
    assert len(web_vulns) >= 1
    v0 = web_vulns[0]
    print(f"    Vulnerability: {v0.vulnerabilityId} | Severity: {v0.severity} | Service: {v0.affectedService}")
    assert v0.vulnerabilityId == "CVE-2026-WEB-RCE"
    assert v0.status == "OPEN"
    print("    [PASS] Active CVE badges mapped to 3D mesh.")

    # 7. Epistemic Provenance Tracking (REAL vs SIMULATION vs PREDICTED)
    print("\n[7/8] Auditing Epistemic Provenance Tracking...")
    device_inspection_engine.set_device_provenance("ATTACKER-EXT", EpistemicProvenanceEnum.REAL_TELEMETRY)
    device_inspection_engine.set_device_provenance("WEB-01", EpistemicProvenanceEnum.SIMULATION)
    device_inspection_engine.set_device_provenance("CLIENT-01", EpistemicProvenanceEnum.PREDICTED)

    vis_att = security_3d_renderer_engine.get_device_security_visual("ATTACKER-EXT")
    vis_web = security_3d_renderer_engine.get_device_security_visual("WEB-01")
    vis_client = security_3d_renderer_engine.get_device_security_visual("CLIENT-01")

    print(f"    ATTACKER-EXT Provenance : {vis_att.provenance.value}")
    print(f"    WEB-01       Provenance : {vis_web.provenance.value}")
    print(f"    CLIENT-01    Provenance : {vis_client.provenance.value}")

    assert vis_att.provenance == EpistemicProvenanceEnum.REAL_TELEMETRY
    assert vis_web.provenance == EpistemicProvenanceEnum.SIMULATION
    assert vis_client.provenance == EpistemicProvenanceEnum.PREDICTED
    print("    [PASS] Ground truth provenance decoupled cleanly.")

    # 8. Guardrail: No UI-Manufactured Security States
    print("\n[8/8] Auditing Single Source of Truth Guardrail...")
    # Attempting to query non-existent device raises KeyError
    trapped = False
    try:
        security_3d_renderer_engine.get_device_security_visual("FAKE-DEVICE-99")
    except KeyError:
        trapped = True
    assert trapped is True
    print("    [PASS] Non-existent devices rejected; zero UI-manufactured false state.")

    # Restore baseline
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    print("\n" + "=" * 80)
    print("       ALL DAY 159 3D SECURITY VISUALIZATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day159_suite()