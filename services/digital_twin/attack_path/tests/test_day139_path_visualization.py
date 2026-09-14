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

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    attack_path_visual_engine.clear()

    # 1. Graph Rendering & ASCII Diagram
    print("[1/10] Auditing ASCII Graph Rendering with Directed Traversal Arrows...")
    chain = ["ATTACKER-EXT", "WEB-01", "DB-01"]
    ascii_diag = attack_path_visual_engine.render_ascii_path_diagram(chain, PathStatusEnum.POSSIBLE)
    print(ascii_diag)
    assert "[ATTACKER-EXT]" in ascii_diag
    assert "[WEB-01]" in ascii_diag
    assert "[DB-01]" in ascii_diag
    assert "▼" in ascii_diag
    print("    [PASS] Directed ASCII graph diagram rendered cleanly.")

    # 2. Node Information Card Inspection
    print("\n[2/10] Auditing Node Visual Inspection Card (WEB-01)...")
    card_web = attack_path_visual_engine.get_node_visual_card("WEB-01")
    print(f"    Device        : {card_web.deviceId} ({card_web.hostname})")
    print(f"    Zone          : {card_web.zone}")
    print(f"    Criticality   : {card_web.assetCriticality}")
    print(f"    Risk Score    : {card_web.riskScore:.2f} [{card_web.riskLevel.value}]")
    print(f"    Open Ports    : {card_web.openPorts}")
    print(f"    Services      : {card_web.services}")
    print(f"    Vulnerabilities: {card_web.activeVulnerabilities}")
    print(f"    Security State: {card_web.securityState}")

    assert card_web.deviceId == "WEB-01"
    assert card_web.zone == "DMZ"
    assert card_web.assetCriticality == "HIGH"
    assert 443 in card_web.openPorts
    assert "CVE-2026-WEB-RCE" in card_web.activeVulnerabilities
    print("    [PASS] Node information card outputs complete security context.")

    # 3. Edge Information Card Inspection
    print("\n[3/10] Auditing Edge Visual Inspection Card (WEB-01 -> DB-01)...")
    card_edge = attack_path_visual_engine.get_edge_visual_card("WEB-01", "DB-01")
    print(f"    Edge          : {card_edge.directedNotation}")
    print(f"    Protocol      : {card_edge.protocol}")
    print(f"    Port          : {card_edge.destinationPort}")
    print(f"    Service       : {card_edge.service}")
    print(f"    Reachability  : {card_edge.reachability}")
    print(f"    Security Ctrl : {card_edge.securityControl}")
    print(f"    Connection ID : {card_edge.connectionId}")

    assert card_edge.sourceNode == "WEB-01"
    assert card_edge.destinationNode == "DB-01"
    assert card_edge.destinationPort == 3306
    assert card_edge.reachability == "REACHABLE"
    assert "FW-RULE-03" in card_edge.securityControl
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

    print(f"    Path ID      : {panel.pathId}")
    print(f"    Source       : {panel.source} -> Target: {panel.targetNode}")
    print(f"    Length       : {panel.pathLength} hops")
    print(f"    Reachability : {panel.reachability}")
    print(f"    Risk Score   : {panel.riskScoreFormatted} [{panel.riskLevel.value}]")
    print(f"    Visual State : {panel.visualState.value}")
    print(f"    Crit Target  : {panel.criticalTarget}")

    assert panel.source == "ATTACKER-EXT"
    assert panel.targetNode == "DB-01"
    assert panel.visualState == PathVisualStateEnum.CRITICAL_PATH
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
    print(f"    Blocked Path Visual State : {panel_blk.visualState.value}")
    assert panel_blk.visualState == PathVisualStateEnum.BLOCKED_PATH

    diag_blk = attack_path_visual_engine.render_ascii_path_diagram(["CLIENT-01", "DB-01"], PathStatusEnum.BLOCKED)
    print(diag_blk)
    assert "BLOCKED" in diag_blk
    print("    [PASS] Blocked paths rendered with distinct visual state.")

    # 6. Critical Asset Identification
    print("\n[6/10] Auditing Critical Asset Target Display...")
    assert panel.criticalTarget is True
    assert panel.riskLevel == RiskLevelTier.CRITICAL
    print("    [PASS] Critical asset flags propagated to visual cards.")

    # 7. Combined XAI + Risk + Graph Explanation Synthesis
    print("\n[7/10] Auditing Multi-Layer Forensic Explanation Synthesis...")
    ml_feats = ["connection frequency", "destination diversity", "abnormal port activity"]
    report = attack_path_visual_engine.generate_comprehensive_explanation(
        path=path_detail,
        risk=risk_record,
        ml_threat_features=ml_feats
    )

    print(report.to_formatted_cli_card())
    assert "connection frequency" in report.mlEvidence
    assert "CVE-2026-" in report.riskEvidence
    assert "DB-01" in report.graphTopologyEvidence
    assert "Resulting in CRITICAL path risk" in report.combinedExplanation
    print("    [PASS] Combined XAI, Risk, and Graph narrative validated.")

    # 8. Multi-Dimensional Graph Filtering: Zone Filter
    print("\n[8/10] Auditing Graph Filtering by Zone (DMZ)...")
    dmz_nodes = attack_path_visual_engine.filter_graph_nodes(GraphVisualizationFilter(zone="DMZ"))
    print(f"    Matched DMZ Nodes: {list(dmz_nodes.keys())}")
    assert "WEB-01" in dmz_nodes
    assert "DB-01" not in dmz_nodes
    print("    [PASS] Zone filtering verified.")

    # 9. Multi-Dimensional Graph Filtering: Vulnerability Filter
    print("\n[9/10] Auditing Graph Filtering by Vulnerability Status (hasVulnerabilities=True)...")
    vuln_nodes = attack_path_visual_engine.filter_graph_nodes(GraphVisualizationFilter(hasVulnerabilities=True))
    print(f"    Vulnerable Nodes: {list(vuln_nodes.keys())}")
    assert "WEB-01" in vuln_nodes
    assert "DB-01" in vuln_nodes
    assert "CLIENT-01" not in vuln_nodes
    print("    [PASS] Vulnerability filtering verified.")

    # 10. Multi-Dimensional Graph Filtering: Critical Target Filter
    print("\n[10/10] Auditing Graph Filtering by Critical Assets Only...")
    crit_nodes = attack_path_visual_engine.filter_graph_nodes(GraphVisualizationFilter(criticalTargetOnly=True))
    print(f"    Critical Asset Nodes: {list(crit_nodes.keys())}")
    assert "DB-01" in crit_nodes
    assert "WEB-01" in crit_nodes  # HIGH criticality
    assert "CLIENT-01" not in crit_nodes  # LOW criticality
    print("    [PASS] Critical asset filtering verified.")

    # Verify Disk Report Persistence
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path" / "path_explanations.json"
    assert out_file.exists()
    print("    [PASS] Explanation reports verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 139 ATTACK PATH VISUALIZATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day139_suite()