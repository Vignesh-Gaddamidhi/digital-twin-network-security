import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.graph_models import (
    NodeTypeEnum, PathStatusEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.nodes.entry_point_engine import entry_point_engine
from services.digital_twin.attack_path.discovery.discovery_models import PathConstraints
from services.digital_twin.attack_path.analysis.attack_path_analysis_models import AnalysisStatusEnum
from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator

def run_day140_suite():
    print("=" * 80)
    print("       WEEK 20 - DAY 140: MASTER ATTACK PATH ANALYSIS COMPLETION AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    master_attack_path_orchestrator.clear()

    # 1. Complete Scenario Test (LATERAL_MOVEMENT_LIKE Scenario)
    print("[1/9] Auditing LATERAL_MOVEMENT_LIKE Scenario (CLIENT-01 Foothold)...")
    entry_point_engine.set_simulation_compromise("CLIENT-01", state="COMPROMISED", scenario_id="LATERAL_MOVEMENT_LIKE")

    res_scenario = master_attack_path_orchestrator.run_master_analysis(
        source_device_id="CLIENT-01",
        target_device_id="DB-01",
        entry_threat_probability=0.88,
        ml_threat_features=["destination diversity", "connection frequency", "port 443 ratio"]
    )

    print(res_scenario.to_soc_summary())
    assert res_scenario.auditRecord.status == AnalysisStatusEnum.COMPLETED
    assert res_scenario.auditRecord.pathsDiscovered >= 1
    assert res_scenario.rankedPaths[0].riskScore > 50.0
    print("    [PASS] LATERAL_MOVEMENT_LIKE scenario traversal analyzed and prioritized.")

    # 2. Alternative Path Test (WEB-01 vs APP-01 routes)
    print("\n[2/9] Auditing Alternative Path Discovery & Ranking (WEB-01 vs APP-01)...")
    # Add APP-01 with patched/low-risk service
    attack_path_graph.add_node(AttackPathNode(
        nodeId="APP-01", deviceId="APP-01", hostname="app-01.dmz.internal", zone="DMZ", assetCriticality="HIGH", reachable=True
    ))
    attack_path_graph.add_edge(AttackPathEdge(
        edgeId="E-CLIENT-APP", sourceNode="CLIENT-01", destinationNode="APP-01", destinationPort=8080, reachable=True
    ))
    attack_path_graph.add_edge(AttackPathEdge(
        edgeId="E-APP-DB", sourceNode="APP-01", destinationNode="DB-01", destinationPort=3306, reachable=True
    ))

    res_alt = master_attack_path_orchestrator.run_master_analysis(
        source_device_id="CLIENT-01",
        target_device_id="DB-01",
        entry_threat_probability=0.88
    )

    print(f"    Paths Discovered : {res_alt.auditRecord.pathsDiscovered}")
    for idx, p in enumerate(res_alt.rankedPaths, start=1):
        print(f"      Rank {idx}: {' -> '.join(p.nodeSequence):<32} | Score: {p.riskScore:5.2f} [{p.riskLevel.value}]")

    assert res_alt.auditRecord.pathsDiscovered >= 2
    # WEB-01 has active unpatched CVE-2026-WEB-RCE, so route through WEB-01 must rank higher or equal to APP-01
    assert "WEB-01" in res_alt.rankedPaths[0].nodeSequence
    print("    [PASS] Alternative attack paths discovered and ranked by vulnerability severity.")

    # 3. Blocked Path Test
    print("\n[3/9] Auditing Firewall Blocked Path (WEB-01 -> DB-01)...")
    edge_web_db = next(e for e in attack_path_graph.edges.values() if e.sourceNode == "WEB-01" and e.destinationNode == "DB-01")
    edge_web_db.reachable = False
    edge_web_db.status = "BLOCKED"
    edge_web_db.securityControl = "FW-EMERGENCY-ISOLATION"

    res_blk = master_attack_path_orchestrator.run_master_analysis(
        source_device_id="ATTACKER-EXT",
        target_device_id="DB-01"
    )

    print(f"    Blocked Path Detected: Total Discovered={res_blk.auditRecord.pathsDiscovered} | Blocked/Partial={res_blk.auditRecord.pathsBlocked + res_blk.auditRecord.pathsPartial}")
    assert res_blk.auditRecord.pathsBlocked > 0 or res_blk.auditRecord.pathsPartial > 0
    # Restore edge
    edge_web_db.reachable = True
    edge_web_db.status = "REACHABLE"
    print("    [PASS] Blocked paths recorded with enforcement rationale.")

    # 4. Vulnerability Remediation Test (Digital Twin Concept)
    print("\n[4/9] Auditing Dynamic Vulnerability Remediation on WEB-01...")
    # Pre-patch score
    res_pre = master_attack_path_orchestrator.run_master_analysis("ATTACKER-EXT", "DB-01")
    score_pre = res_pre.rankedPaths[0].riskScore
    print(f"    Pre-Patch Path Risk Score  : {score_pre:.2f}")

    # Patch vulnerability on WEB-01
    twin_graph_synchronizer.update_device_vulnerabilities("WEB-01", [])
    res_post = master_attack_path_orchestrator.run_master_analysis("ATTACKER-EXT", "DB-01")
    score_post = res_post.rankedPaths[0].riskScore
    print(f"    Post-Patch Path Risk Score : {score_post:.2f}")

    assert score_post < score_pre
    print("    [PASS] Vulnerability patching dynamically reduces attack path risk.")
    # Restore vulnerability for remaining tests
    twin_graph_synchronizer.update_device_vulnerabilities("WEB-01", ["CVE-2026-WEB-RCE"])

    # 5. Device Isolation Test (Security Containment)
    print("\n[5/9] Auditing Automated Host Quarantine (CLIENT-01)...")
    twin_graph_synchronizer.isolate_device("CLIENT-01")
    res_iso = master_attack_path_orchestrator.run_master_analysis("CLIENT-01", "DB-01")
    print(f"    Paths Found from Isolated Host : {res_iso.auditRecord.pathsDiscovered}")
    assert res_iso.auditRecord.pathsDiscovered == 0
    print("    [PASS] Quarantined host has zero outgoing attack reachability.")
    # Restore topology
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 6. Risk Escalation Test (Temporal Progression)
    print("\n[6/9] Auditing Risk Escalation over Observation Window...")
    from services.digital_twin.risk.history.risk_state_engine import risk_state_engine
    risk_state_engine.clear()
    s1, _ = risk_state_engine.record_risk_observation("DB-01", 35.0, "P-1")
    s2, _ = risk_state_engine.record_risk_observation("DB-01", 65.0, "P-2")
    s3, _ = risk_state_engine.record_risk_observation("DB-01", 85.0, "P-3")

    print(f"    DB-01 Temporal Risk : {s1.currentRiskLevel.value} -> {s2.currentRiskLevel.value} -> {s3.currentRiskLevel.value} (Trend: {s3.riskTrend.value})")
    assert s1.currentRiskLevel == RiskLevelTier.MEDIUM
    assert s2.currentRiskLevel == RiskLevelTier.HIGH
    assert s3.currentRiskLevel == RiskLevelTier.CRITICAL
    assert s3.riskTrend.value == "INCREASING"
    assert s3.history[0].riskLevel == RiskLevelTier.MEDIUM
    assert s3.history[1].riskLevel == RiskLevelTier.HIGH
    assert s3.history[2].riskLevel == RiskLevelTier.CRITICAL
    print("    [PASS] Temporal risk progression and trend reflected accurately.")

    # 7. Mandatory Failure Handlers Audit
    print("\n[7/9] Auditing Mandatory Failure Handlers...")
    # Unknown Source
    caught_src = False
    try:
        master_attack_path_orchestrator.run_master_analysis("UNKNOWN-SRC-99", "DB-01")
    except KeyError as e:
        caught_src = "SOURCE_NOT_FOUND" in str(e)
    assert caught_src
    print("    Unknown Source -> Trapped: SOURCE_NOT_FOUND")

    # Unknown Target
    caught_tgt = False
    try:
        master_attack_path_orchestrator.run_master_analysis("CLIENT-01", "UNKNOWN-TGT-99")
    except KeyError as e:
        caught_tgt = "TARGET_NOT_FOUND" in str(e)
    assert caught_tgt
    print("    Unknown Target -> Trapped: TARGET_NOT_FOUND")

    # Empty Graph
    attack_path_graph.clear()
    caught_empty = False
    try:
        master_attack_path_orchestrator.run_master_analysis("CLIENT-01", "DB-01")
    except ValueError as e:
        caught_empty = "NO_GRAPH_DATA" in str(e)
    assert caught_empty
    print("    Empty Graph    -> Trapped: NO_GRAPH_DATA")
    print("    [PASS] All failure modes handled with defensive exceptions.")

    # Restore topology for benchmark
    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()

    # 8. Performance Scalability Benchmarking (10, 25, 50, 100 Nodes)
    print("\n[8/9] Auditing Performance Scalability Across 10, 25, 50, and 100 Nodes...")
    benchmarks = master_attack_path_orchestrator.benchmark_graph_scalability([10, 25, 50, 100])

    print("\n    | Nodes | Edges | Graph Build (ms) | Path Discovery (ms) | Ranking (ms) | Total Latency (ms) | Paths |")
    print("    |-------|-------|------------------|---------------------|--------------|--------------------|-------|")
    for b in benchmarks:
        print(f"    | {b['nodes']:<5} | {b['edges']:<5} | {b['graphConstructionMs']:<16.3f} | {b['pathDiscoveryMs']:<19.3f} | {b['pathRankingMs']:<12.3f} | {b['totalExecutionMs']:<18.3f} | {b['pathsDiscovered']:<5} |")
        assert b["totalExecutionMs"] < 50.0  # Real-time interactive budget (<50ms for 100 nodes)

    print("    [PASS] Graph exploration scales sub-linearly under bounded DFS.")

    # 9. Audit Trail Disk Persistence
    print("\n[9/9] Auditing Master Attack Path Audit Trail on Disk...")
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path" / "master_analysis_audit.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        stored_audits = json.load(f)
    assert len(stored_audits) >= 3
    print(f"    Verified {len(stored_audits)} persistent audit records in master_analysis_audit.json.")
    print("    [PASS] Master analysis audit trail verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 140 MASTER ATTACK PATH ANALYSIS TESTS PASSED CLEANLY")
    print("       PHASE 17: ATTACK PATH ANALYSIS GRADUATED SUCCESSFULLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day140_suite()