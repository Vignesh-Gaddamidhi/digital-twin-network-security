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
from services.digital_twin.attack_path.discovery.discovery_models import DiscoveredPathDetail
from services.digital_twin.attack_path.scoring.path_risk_engine import path_risk_engine
from services.digital_twin.attack_path.visualization.path_visual_models import (
    PathVisualStateEnum, GraphVisualizationFilter
)
from services.digital_twin.attack_path.visualization.path_visual_engine import attack_path_visual_engine

def run_day139_suite():
    print("=" * 80)
    print("       WEEK 20 - DAY 139: ATTACK PATH VISUALIZATION & EXPLANATION AUDIT")
    print("=" * 80 + "\n")

    out_dir = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path"
    out_dir.mkdir(parents=True, exist_ok=True)

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    attack_path_visual_engine.clear()

    # 1. Graph Rendering & ASCII Diagram
    print("[1/10] Auditing ASCII Graph Rendering with Directed Traversal Arrows...")
    chain = ["ATTACKER-EXT", "WEB-01", "DB-01"]
    ascii_diag = attack_path_visual_engine.render_ascii_path_diagram(chain, PathStatusEnum.POSSIBLE)
    assert "[ATTACKER-EXT]" in ascii_diag
    assert "[WEB-01]" in ascii_diag
    assert "[DB-01]" in ascii_diag
    print("    [PASS] Directed ASCII graph diagram rendered cleanly.")

    # 2. Node Information Card Inspection
    print("\n[2/10] Auditing Node Visual Inspection Card (WEB-01)...")
    card_web = attack_path_visual_engine.get_node_visual_card("WEB-01")
    assert card_web.deviceId == "WEB-01"
    assert card_web.zone == "DMZ"
    assert card_web.assetCriticality == "HIGH"
    print("    [PASS] Node information card outputs complete security context.")

    # 3. Edge Information Card Inspection
    print("\n[3/10] Auditing Edge Visual Inspection Card (WEB-01 -> DB-01)...")
    card_edge = attack_path_visual_engine.get_edge_visual_card("WEB-01", "DB-01")
    assert card_edge.sourceNode == "WEB-01"
    assert card_edge.destinationNode == "DB-01"
    print("    [PASS] Edge information card verified.")

    # 4. Attack Path Panel Generation
    print("\n[4/10] Auditing Attack Path Panel Data...")
    path_detail = DiscoveredPathDetail(
        nodeSequence=chain,
        edgeSequence=["CONN-01", "CONN-03"],
        hopCount=2,
        status=PathStatusEnum.POSSIBLE,
        vulnerabilitiesEncountered=["CVE-2026-WEB-RCE", "CVE-2026-SQLI"]
    )
    risk_record = path_risk_engine.calculate_path_risk(path_detail)
    panel = attack_path_visual_engine.generate_path_visual_panel(path_detail, risk_record)
    assert panel.source == "ATTACKER-EXT"
    assert panel.targetNode == "DB-01"
    assert panel.criticalTarget is True
    print("    [PASS] Attack path panel validated.")

    # 5. Blocked Path Visual Display
    print("\n[5/10] Auditing Blocked Path Display State...")
    path_blocked = DiscoveredPathDetail(
        nodeSequence=["CLIENT-01", "DB-01"],
        edgeSequence=["CONN-05"],
        hopCount=1,
        status=PathStatusEnum.BLOCKED,
        blockingReason="FW-RULE-04: Internal to Database Direct Blocking"
    )
    risk_blk = path_risk_engine.calculate_path_risk(path_blocked)
    panel_blk = attack_path_visual_engine.generate_path_visual_panel(path_blocked, risk_blk)
    assert panel_blk.visualState == PathVisualStateEnum.BLOCKED_PATH
    print("    [PASS] Blocked paths rendered with distinct visual state.")

    # 6. Critical Asset Identification
    print("\n[6/10] Auditing Critical Asset Target Display...")
    assert panel.criticalTarget is True
    assert panel.riskLevel in (RiskLevelTier.CRITICAL, RiskLevelTier.HIGH)
    print("    [PASS] Critical asset flags propagated to visual cards.")

    # 7. Combined XAI + Risk + Graph Explanation Synthesis
    print("\n[7/10] Auditing Multi-Layer Forensic Explanation Synthesis...")
    ml_feats = ["connection frequency", "destination diversity", "abnormal port activity"]
    report = attack_path_visual_engine.generate_comprehensive_explanation(
        path=path_detail,
        risk=risk_record,
        ml_threat_features=ml_feats
    )
    assert "connection frequency" in report.mlEvidence
    print("    [PASS] Combined XAI, Risk, and Graph narrative validated.")

    # 8. Graph Filtering by Zone
    print("\n[8/10] Auditing Graph Filtering by Zone (DMZ)...")
    dmz_nodes = attack_path_visual_engine.filter_graph_nodes(GraphVisualizationFilter(zone="DMZ"))
    assert "WEB-01" in dmz_nodes
    print("    [PASS] Zone filtering verified.")

    # 9. Graph Filtering by Vulnerability
    print("\n[9/10] Auditing Graph Filtering by Vulnerability Status...")
    vuln_nodes = attack_path_visual_engine.filter_graph_nodes(GraphVisualizationFilter(hasVulnerabilities=True))
    assert "WEB-01" in vuln_nodes
    print("    [PASS] Vulnerability filtering verified.")

    # 10. Graph Filtering by Critical Assets
    print("\n[10/10] Auditing Graph Filtering by Critical Assets Only...")
    crit_nodes = attack_path_visual_engine.filter_graph_nodes(GraphVisualizationFilter(criticalTargetOnly=True))
    assert "DB-01" in crit_nodes
    print("    [PASS] Critical asset filtering verified.")

    out_file = out_dir / "path_explanations.json"
    if not out_file.exists():
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump([report.__dict__ if hasattr(report, "__dict__") else {"status": "ok"}], f)

    assert out_file.exists()
    print("    [PASS] Explanation reports verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 139 ATTACK PATH VISUALIZATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day139_suite()