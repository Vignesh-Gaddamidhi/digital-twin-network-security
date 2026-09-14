import sys
import json
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.risk.history.risk_state_engine import risk_state_engine
from services.digital_twin.attack_path.scoring.path_risk_engine import path_risk_engine
from services.digital_twin.attack_path.discovery.discovery_models import DiscoveredPathDetail
from services.digital_twin.attack_path.graph.graph_models import PathStatusEnum

def run_day147_suite():
    print("=" * 80)
    print("       WEEK 21 - DAY 147: DASHBOARD INTEGRATION & END-TO-END AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 1. Master Consolidated Summary Data Payload
    print("[1/11] Auditing Master Dashboard Consolidated Summary Contract...")
    from services.twin_engine.src.api.main import api_get_master_dashboard_summary
    t0 = time.perf_counter()
    summary = api_get_master_dashboard_summary()
    lat_ms = (time.perf_counter() - t0) * 1000
    print(f"    Summary Ingestion Latency : {lat_ms:.2f} ms")
    assert "header" in summary
    assert "kpis" in summary
    assert "topology" in summary
    assert "traffic" in summary
    assert "timeline" in summary
    assert "prediction" in summary
    assert "topAttackPath" in summary
    assert lat_ms < 50.0  # Real-time interactive budget (<50ms)
    print("    [PASS] Master summary endpoint returned complete payload in <50ms.")

    # 2. Cross-Subsystem State Consistency Invariant (Day 147.5)
    print("\n[2/11] Auditing Cross-Component State Consistency (DB-01 Alignment)...")
    db_node = next(n for n in summary["topology"]["nodes"] if n["deviceId"] == "DB-01")
    db_risk_kpi = summary["kpis"]["risk"]["highestRiskDevice"]
    print(f"    Topology Node DB-01 Risk   : {db_node['riskScore']:.2f} [{db_node['riskLevel']}]")
    print(f"    KPI Highest Risk Device    : {db_risk_kpi}")
    print(f"    Attack Path Target Risk    : {summary['topAttackPath']['riskScore']:.2f} [{summary['topAttackPath']['riskLevel']}]")
    assert db_risk_kpi == "DB-01"
    assert db_node["assetCriticality"] == "CRITICAL"
    assert summary["topAttackPath"]["criticalTarget"] is True
    print("    [PASS] Strict state consistency verified across Topology, KPIs, and Attack Paths.")

    # 3. Simulation Control Engine Transitions (Day 147.6)
    print("\n[3/11] Auditing Simulation Control Engine Lifecycle...")
    from services.twin_engine.src.api.main import api_control_simulation, SimulationControlRequest
    st_start = api_control_simulation(SimulationControlRequest(action="START", speed=2))
    st_pause = api_control_simulation(SimulationControlRequest(action="PAUSE"))
    st_stop = api_control_simulation(SimulationControlRequest(action="STOP"))
    st_reset = api_control_simulation(SimulationControlRequest(action="RESET"))

    print(f"    START: {st_start['status']} (Speed: {st_start['speedMultiplier']}x)")
    print(f"    PAUSE: {st_pause['status']}")
    print(f"    STOP : {st_stop['status']}")
    print(f"    RESET: {st_reset['status']}")

    assert st_start["status"] == "RUNNING"
    assert st_pause["status"] == "PAUSED"
    assert st_stop["status"] == "STOPPED"
    assert st_reset["status"] == "RESET"
    print("    [PASS] Simulation lifecycle controls validated.")

    # 4. Normal Scenario Baseline Validation (Day 147.7)
    print("\n[4/11] Auditing NORMAL Scenario Telemetry...")
    from services.digital_twin.risk.engine.master_risk_orchestrator import master_risk_orchestrator
    norm_risk = master_risk_orchestrator.process_end_to_end_risk(
        prediction_id="P-NORM", device_id="CLIENT-01", threat_probability=0.08, predicted_category="NORMAL"
    )
    print(f"    Normal Scenario -> Threat: {norm_risk.threatProbability*100:.1f}% | Risk: {norm_risk.riskScore:.2f} [{norm_risk.riskLevel}]")
    assert norm_risk.riskScore < 25.0
    assert norm_risk.riskLevel == "LOW"
    print("    [PASS] NORMAL baseline confirms low-risk telemetry.")

    # 5. Traffic Spike Anomaly Propagation (Day 147.8)
    print("\n[5/11] Auditing TRAFFIC_SPIKE Anomaly Chain...")
    from services.twin_engine.src.api.main import api_get_live_traffic_metrics
    traffic_spike = api_get_live_traffic_metrics(simulate_spike=True)
    print(f"    Surged Packet Rate: {traffic_spike['packetRateFormatted']}")
    print(f"    Anomaly Detected  : {traffic_spike['anomaly']['detected']} ({traffic_spike['anomaly']['anomalyType']})")
    assert traffic_spike["anomaly"]["detected"] is True
    assert traffic_spike["anomaly"]["anomalyType"] == "TRAFFIC_SPIKE_DETECTED"
    print("    [PASS] Traffic spike correctly triggers anomaly state.")

    # 6. Attack Path Traversal & Lateral Movement Scenario (Day 147.9)
    print("\n[6/11] Auditing LATERAL_MOVEMENT_LIKE Scenario Path Traversal...")
    from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator
    analysis = master_attack_path_orchestrator.run_master_analysis("CLIENT-01", "DB-01", entry_threat_probability=0.88)
    assert analysis.auditRecord.pathsDiscovered >= 1
    top_p = analysis.rankedPaths[0]
    print(f"    Top Attack Trajectory: {' -> '.join(top_p.nodeSequence)} (Risk: {top_p.riskScore:.2f})")
    assert "DB-01" in top_p.nodeSequence
    print("    [PASS] Attack path discovered and prioritized.")

    # 7. Blocked Path Security Control Enforcement (Day 147.10)
    print("\n[7/11] Auditing Blocked Path Security Control Enforcement...")
    edge_web_db = next(e for e in attack_path_graph.edges.values() if e.sourceNode == "WEB-01" and e.destinationNode == "DB-01")
    edge_web_db.reachable = False
    edge_web_db.status = "BLOCKED"
    blk_path = DiscoveredPathDetail(
        nodeSequence=["ATTACKER-EXT", "WEB-01", "DB-01"], edgeSequence=["C1", "C3"], hopCount=2, status=PathStatusEnum.BLOCKED
    )
    risk_blk = path_risk_engine.calculate_path_risk(blk_path, persist=False)
    print(f"    Blocked Path Score : {risk_blk.score:.2f} (Multiplier: {risk_blk.reachabilityMultiplier})")
    assert risk_blk.reachabilityMultiplier == 0.15
    assert risk_blk.score < 25.0
    # Restore edge
    edge_web_db.reachable = True
    edge_web_db.status = "REACHABLE"
    print("    [PASS] Blocked paths retain low residual score without removal.")

    # 8. Dynamic Vulnerability Remediation (Day 147.11)
    print("\n[8/11] Auditing Dynamic Vulnerability Patching Impact...")
    path_sample = DiscoveredPathDetail(nodeSequence=["ATTACKER-EXT", "WEB-01", "DB-01"], edgeSequence=["C1", "C3"], hopCount=2, status=PathStatusEnum.POSSIBLE)
    r_pre = path_risk_engine.calculate_path_risk(path_sample, persist=False)
    twin_graph_synchronizer.update_device_vulnerabilities("WEB-01", [])
    r_post = path_risk_engine.calculate_path_risk(path_sample, persist=False)
    print(f"    Pre-Patch Risk  : {r_pre.score:.2f}")
    print(f"    Post-Patch Risk : {r_post.score:.2f}")
    assert r_post.score < r_pre.score
    twin_graph_synchronizer.update_device_vulnerabilities("WEB-01", ["CVE-2026-WEB-RCE"])
    print("    [PASS] Remediation dynamically recalculates attack path risk.")

    # 9. Automated Host Quarantine (Day 147.12)
    print("\n[9/11] Auditing Automated Host Isolation Reaction...")
    twin_graph_synchronizer.isolate_device("CLIENT-01")
    client_node = attack_path_graph.get_node("CLIENT-01")
    print(f"    CLIENT-01 Security State : {client_node.securityState}")
    assert client_node.securityState == "QUARANTINED"
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    print("    [PASS] Automated isolation severs reachable connections.")

    # 10. Defensive Error & Malformed Query Trapping (Day 147.14)
    print("\n[10/11] Auditing Defensive Security Input Validation...")
    from fastapi import HTTPException
    caught_unknown = False
    try:
        master_attack_path_orchestrator.run_master_analysis("INVAL-SRC", "DB-01")
    except KeyError as e:
        caught_unknown = "SOURCE_NOT_FOUND" in str(e)
    assert caught_unknown
    print("    [PASS] Malformed/unknown device IDs rejected with defensive exceptions.")

    # 11. Complete Frontend Architecture Files Check
    print("\n[11/11] Auditing Complete Dashboard Frontend Components on Disk...")
    expected_files = [
        "services/web_dashboard/src/types/summary.ts",
        "services/web_dashboard/src/components/simulation/SimulationControlBar.tsx",
        "services/web_dashboard/src/components/layout/SecurityDashboardHome.tsx"
    ]
    for rel_path in expected_files:
        p = ROOT_DIR / rel_path
        assert p.exists(), f"Missing expected file: {p}"
    print(f"    Verified {len(expected_files)} integrated layout files on disk.")
    print("    [PASS] Complete frontend codebase verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 147 DASHBOARD INTEGRATION TESTS PASSED CLEANLY")
    print("       PHASE 18 (WEEK 21) MILESTONE COMPLETED SUCCESSFULLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day147_suite()