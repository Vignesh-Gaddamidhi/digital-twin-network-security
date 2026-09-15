import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.attacks.attack_path_dashboard_models import PathFilterTypeEnum
from frontend.attacks.attack_path_dashboard_engine import attack_path_dashboard_engine

def run_day149_suite():
    print("=" * 80)
    print("       WEEK 22 - DAY 149: ATTACK PATH DASHBOARD AUDIT")
    print("=" * 80 + "\n")

    attack_path_dashboard_engine._seed_default_analysis()

    # 1. Path Display & CLI Panel Layout
    print("[1/9] Auditing Attack Path Dashboard Snapshot & CLI Layout...")
    snap = attack_path_dashboard_engine.generate_dashboard_snapshot()
    cli_panel = snap.render_cli_panel()
    print(cli_panel)

    assert snap.totalDiscoveredPaths >= 2
    assert len(snap.rankedPaths) >= 2
    assert "ATTACK PATH ANALYSIS DASHBOARD" in cli_panel
    print("    [PASS] Attack path dashboard panel rendered cleanly.")

    # 2. Path Ranking (Descending Risk Order)
    print("\n[2/9] Auditing Attack Path Ranking Integrity...")
    r_paths = snap.rankedPaths
    for p in r_paths:
        print(f"    Rank #{p.rank}: {' -> '.join(p.nodeSequence):<32} Risk: {p.riskScore:5.2f} [{p.riskLevel.value}] Status: {p.status}")

    assert r_paths[0].rank == 1
    assert r_paths[0].riskScore >= r_paths[1].riskScore
    assert r_paths[0].riskLevel == RiskLevelTier.CRITICAL
    print("    [PASS] Paths ranked deterministically by risk score.")

    # 3. Path Selection & Detail Inspection
    print("\n[3/9] Auditing Path Selection & Detail Inspection...")
    target_pid = r_paths[0].pathId
    sel_snap = attack_path_dashboard_engine.select_path(target_pid)
    detail = sel_snap.selectedPathDetail
    assert detail is not None
    assert detail.selectedPath.pathId == target_pid

    print(f"    Selected Path ID : {detail.selectedPath.pathId}")
    print(f"    Traversal Chain  : {' -> '.join(detail.selectedPath.nodeSequence)}")
    print(f"    Reachability     : {detail.selectedPath.reachability}")
    print(f"    Target Node      : {detail.selectedPath.targetNode}")
    assert detail.selectedPath.targetNode == "DB-01"
    print("    [PASS] Path selection extracts complete inspection details.")

    # 4. Topology Highlighting State Synchronization
    print("\n[4/9] Auditing Topology Canvas Highlighting Synchronization...")
    hl = detail.highlightState
    print(f"    Active Path ID    : {hl.activePathId}")
    print(f"    Highlighted Nodes : {hl.highlightedNodes}")
    print(f"    Highlighted Edges : {hl.highlightedEdges}")
    print(f"    Target Node ID    : {hl.targetNodeId}")

    assert hl.activePathId == target_pid
    assert "CLIENT-01" in hl.highlightedNodes
    assert "DB-01" in hl.highlightedNodes
    assert len(hl.highlightedEdges) >= 2
    print("    [PASS] Nodes and edges synced for canvas highlighting.")

    # 5. Filter by Reachable Paths
    print("\n[5/9] Auditing Path Filtering by REACHABLE...")
    snap_reach = attack_path_dashboard_engine.generate_dashboard_snapshot(PathFilterTypeEnum.REACHABLE)
    for p in snap_reach.rankedPaths:
        print(f"    Reachable Path: {' -> '.join(p.nodeSequence)} ({p.reachability})")
        assert p.reachability == "REACHABLE"
    assert len(snap_reach.rankedPaths) >= 1
    print("    [PASS] Reachable paths filter verified.")

    # 6. Filter by Blocked Paths
    print("\n[6/9] Auditing Path Filtering by BLOCKED...")
    snap_blk = attack_path_dashboard_engine.generate_dashboard_snapshot(PathFilterTypeEnum.BLOCKED)
    for p in snap_blk.rankedPaths:
        print(f"    Blocked Path: {' -> '.join(p.nodeSequence)} Status: {p.status}")
        assert p.status == "BLOCKED"
    assert len(snap_blk.rankedPaths) >= 1
    print("    [PASS] Blocked paths filter verified.")

    # 7. Path -> Risk Factor Decomposition
    print("\n[7/9] Auditing Path Contextual Risk Decomposition...")
    print(f"    Threat Probability      : {detail.threatProbability*100:.0f}%")
    print(f"    Max Intermediate Risk   : {detail.maxIntermediateRisk}")
    print(f"    Target Criticality      : {detail.targetCriticalityWeight}")
    print(f"    Vulnerability Weight    : {detail.vulnerabilityWeight}")
    print(f"    Attack Impact           : {detail.attackImpactWeight}")

    assert detail.threatProbability == 0.88
    assert detail.targetCriticalityWeight == 1.00
    print("    [PASS] Multiplicative risk factors decomposed properly.")

    # 8. Crown Jewel Target Verification
    print("\n[8/9] Auditing Crown Jewel Target Identification...")
    assert detail.selectedPath.criticalTarget is True
    assert detail.selectedPath.targetNode == "DB-01"
    print("    [PASS] Database target designated as critical crown jewel.")

    # 9. Path -> XAI Attribution & Mitigation Narrative
    print("\n[9/9] Auditing XAI Attribution & Actionable Mitigation Guidance...")
    print(f"    XAI Attribution : {detail.xaiAttributionText}")
    print(f"    Origin Features : {detail.originatingFeatures}")
    print(f"    Containment     : {detail.recommendedContainment}")

    assert "Random Forest" in detail.xaiAttributionText
    assert "connection_frequency" in detail.originatingFeatures
    assert "network segmentation" in detail.recommendedContainment
    print("    [PASS] End-to-end XAI and mitigation linkage verified.")

    print("\n" + "=" * 80)
    print("       ALL DAY 149 ATTACK PATH DASHBOARD TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day149_suite()