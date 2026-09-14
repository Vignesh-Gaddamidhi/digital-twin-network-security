import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.graph_models import NodeTypeEnum
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.nodes.entry_point_models import (
    StateSourceEnum, TargetTypeEnum
)
from services.digital_twin.attack_path.nodes.entry_point_engine import entry_point_engine

def run_day136_suite():
    print("=" * 80)
    print("       WEEK 20 - DAY 136: ATTACKER, ENTRY POINT & COMPROMISE MODEL AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    entry_point_engine.clear()

    # 1. Attacker Node Creation
    print("[1/10] Auditing Synthetic Attacker Node Creation...")
    attacker = entry_point_engine.create_attacker_node(
        node_id="ATTACKER-01",
        hostname="adversary.external.net",
        ip="198.51.100.24"
    )
    print(f"    Attacker Node : {attacker.nodeId} (Type: {attacker.nodeType.value}, Zone: {attacker.zone})")
    assert attacker.nodeId == "ATTACKER-01"
    assert attacker.nodeType == NodeTypeEnum.ATTACKER
    assert attacker.zone == "INTERNET"
    print("    [PASS] Attacker node validated.")

    # 2. Entry-Point Evaluation
    print("\n[2/10] Auditing Candidate Entry-Point Evaluation...")
    score_web = entry_point_engine.evaluate_entry_point("WEB-01", threat_probability=0.87)
    print(f"    WEB-01 Entry Score : {score_web.compositeScore:.4f} (Exposure: {score_web.exposure}, Reach: {score_web.reachability})")
    assert score_web.compositeScore > 0.60
    assert score_web.reachability == 1.0
    print("    [PASS] Candidate entry point evaluated successfully.")

    # 3. Compromised Device State
    print("\n[3/10] Auditing Explicit Scenario Compromise Setting...")
    comp_client = entry_point_engine.set_simulation_compromise(
        device_id="CLIENT-01",
        state="COMPROMISED",
        scenario_id="LATERAL_MOVEMENT_LIKE"
    )
    print(f"    CLIENT-01 State : {comp_client.confirmedState} (Source: {comp_client.stateSource.value})")
    assert comp_client.confirmedState == "COMPROMISED"
    assert comp_client.scenarioId == "LATERAL_MOVEMENT_LIKE"
    print("    [PASS] Compromised device state recorded.")

    # 4. Simulation-Only Compromise (State Source Isolation)
    print("\n[4/10] Auditing State Source Separation (Simulation vs ML Predicted)...")
    comp_pred = entry_point_engine.set_predicted_compromise("CLIENT-01", predicted_state="AT_RISK")
    print(f"    Confirmed State : {comp_pred.confirmedState} (Scenario-controlled)")
    print(f"    Predicted State : {comp_pred.predictedState} (ML-inferred)")
    assert comp_pred.confirmedState == "COMPROMISED"
    assert comp_pred.predictedState == "AT_RISK"
    assert comp_pred.stateSource == StateSourceEnum.ML_PREDICTED_STATE
    print("    [PASS] ML prediction does not overwrite confirmed simulation ground truth.")

    # 5. Candidate Entry Point Scoring Comparison (WEB-01 vs CLIENT-01)
    print("\n[5/10] Auditing Entry Point Scoring Divergence...")
    score_client = entry_point_engine.evaluate_entry_point("CLIENT-01", threat_probability=0.20)
    print(f"    WEB-01    (DMZ, Exposed, Vuln) : {score_web.compositeScore:.4f}")
    print(f"    CLIENT-01 (Internal LAN)       : {score_client.compositeScore:.4f}")
    assert score_web.compositeScore > score_client.compositeScore
    print("    [PASS] Entry point scoring accurately reflects exposure and perimeter risk.")

    # 6. Attack Target Definition Creation
    print("\n[6/10] Auditing Attack Target Definition Creation (DB-01 Crown Jewel)...")
    target_db = entry_point_engine.register_target(
        device_id="DB-01",
        target_type=TargetTypeEnum.DATABASE,
        service_name="MYSQL",
        port=3306,
        description="Core Customer Relational Database"
    )
    print(f"    Target Registered: {target_db.deviceId} (Type: {target_db.targetType.value}, Crit: {target_db.assetCriticality})")
    assert target_db.deviceId == "DB-01"
    assert target_db.targetType == TargetTypeEnum.DATABASE
    assert target_db.assetCriticality == "CRITICAL"
    print("    [PASS] Attack target registered.")

    # 7. External Exposure Verification
    print("\n[7/10] Auditing Zone-Based External Exposure Calculation...")
    assert score_web.exposure == 1.0   # DMZ
    assert score_client.exposure == 0.5 # Internal
    print("    [PASS] External exposure factors validated.")

    # 8. Vulnerable Service Impact on Entry Score
    print("\n[8/10] Auditing Vulnerable Service Impact...")
    assert score_web.vulnerability == 1.0  # Has CVE-2026-WEB-RCE
    assert score_client.vulnerability == 0.2 # None
    print("    [PASS] Vulnerability status correctly inflates entry-point priority.")

    # 9. Isolated Device Rejection
    print("\n[9/10] Auditing Reachability of Isolated / Quarantined Device...")
    entry_point_engine.set_simulation_compromise("CLIENT-01", state="ISOLATED")
    score_isolated = entry_point_engine.evaluate_entry_point("CLIENT-01")
    print(f"    Isolated CLIENT-01 Reachability: {score_isolated.reachability}")
    assert score_isolated.reachability == 0.0
    print("    [PASS] Isolated host reachability zeroed out.")

    # 10. Unreachable Device Handling
    print("\n[10/10] Auditing Unreachable / Disconnected Node Scoring...")
    score_dns = entry_point_engine.evaluate_entry_point("DNS-SERVER-01")
    print(f"    DNS-SERVER-01 Entry Score: {score_dns.compositeScore:.4f} (Exposure: {score_dns.exposure})")
    assert score_dns.compositeScore < score_web.compositeScore
    print("    [PASS] Unreachable entry paths penalized.")

    print("\n" + "=" * 80)
    print("       ALL DAY 136 ENTRY POINT & COMPROMISE MODEL TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    run_day136_suite()