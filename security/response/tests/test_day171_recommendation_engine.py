import sys
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from security.response.models.action import ResponseActionType
from security.response.models.recommendation import (
    ResponseRecommendation, RecommendationStatusEnum, RecommendationPriorityEnum
)
from security.response.engine.recommendation_engine import (
    ResponseRecommendationEngine, response_recommendation_engine
)

def run_day171_suite():
    print("=" * 80)
    print("       WEEK 25 - DAY 171: RESPONSE RECOMMENDATION ENGINE AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    if "WEB-01" in attack_path_graph.nodes:
        attack_path_graph.nodes["WEB-01"].securityState = "NORMAL"

    # 1. Critical Lateral Threat Mapping -> ISOLATE_DEVICE
    print("[1/9] Auditing Critical Lateral Threat Mapping -> ISOLATE_DEVICE...")
    rec_isolate = response_recommendation_engine.formulate_recommendation(
        alert_id="ALT-20260916-101",
        prediction_id="PRD-20260916-102",
        device_id="WEB-01",
        risk_score=86.5,
        predicted_category="LATERAL_MOVEMENT",
        prediction_confidence=0.96,
        xai_features=["Repeated RPC connection attempts", "High target asset criticality"]
    )
    print(f"    Action Recommended: {rec_isolate.recommendedAction.value}")
    print(f"    Priority          : {rec_isolate.priority.value}")
    print(f"    Reason            : {rec_isolate.reason}")

    assert rec_isolate.recommendedAction == ResponseActionType.ISOLATE_DEVICE
    assert rec_isolate.priority == RecommendationPriorityEnum.CRITICAL
    assert rec_isolate.simulationRequired is True
    print("    [PASS] Critical threat mapped to ISOLATE_DEVICE.")

    # 2. Port Reconnaissance Mapping -> BLOCK_CONNECTION
    print("\n[2/9] Auditing Reconnaissance Anomaly Mapping -> BLOCK_CONNECTION...")
    rec_block = response_recommendation_engine.formulate_recommendation(
        alert_id="ALT-20260916-201",
        prediction_id="PRD-20260916-202",
        device_id="WEB-01",
        risk_score=68.0,
        predicted_category="PORT_SCAN",
        prediction_confidence=0.92,
        xai_features=["Unassigned port probe detected", "Rapid sequence TCP SYN"]
    )
    print(f"    Action Recommended: {rec_block.recommendedAction.value}")
    print(f"    Priority          : {rec_block.priority.value}")

    assert rec_block.recommendedAction == ResponseActionType.BLOCK_CONNECTION
    assert rec_block.priority == RecommendationPriorityEnum.HIGH
    print("    [PASS] Port scan mapped to BLOCK_CONNECTION.")

    # 3. Vulnerable Service Exploit -> DISABLE_SERVICE
    print("\n[3/9] Auditing Service Exploitation -> DISABLE_SERVICE...")
    rec_svc = response_recommendation_engine.formulate_recommendation(
        alert_id="ALT-20260916-301",
        prediction_id="PRD-20260916-302",
        device_id="WEB-01",
        risk_score=62.0,
        predicted_category="SERVICE_EXPLOIT",
        has_open_vulnerabilities=True,
        target_service="Apache_HTTP_80"
    )
    print(f"    Action Recommended: {rec_svc.recommendedAction.value}")
    print(f"    Target Service    : {rec_svc.targetService}")

    assert rec_svc.recommendedAction == ResponseActionType.DISABLE_SERVICE
    assert rec_svc.targetService == "Apache_HTTP_80"
    print("    [PASS] Vulnerable service exploit mapped to DISABLE_SERVICE.")

    # 4. Workstation Client Anomaly -> QUARANTINE_ENDPOINT
    print("\n[4/9] Auditing Client Workstation Anomaly -> QUARANTINE_ENDPOINT...")
    rec_quar = response_recommendation_engine.formulate_recommendation(
        alert_id="ALT-20260916-401",
        prediction_id="PRD-20260916-402",
        device_id="CLIENT-01",
        risk_score=64.0,
        predicted_category="ENDPOINT_ANOMALY"
    )
    print(f"    Action Recommended: {rec_quar.recommendedAction.value}")
    print(f"    Target Host       : {rec_quar.deviceId}")

    assert rec_quar.recommendedAction == ResponseActionType.QUARANTINE_ENDPOINT
    print("    [PASS] Client endpoint anomaly mapped to QUARANTINE_ENDPOINT.")

    # 5. Moderate Risk Elevation -> INCREASE_SECURITY_LEVEL
    print("\n[5/9] Auditing Moderate Risk Posture -> INCREASE_SECURITY_LEVEL...")
    rec_sec = response_recommendation_engine.formulate_recommendation(
        alert_id="ALT-20260916-501",
        prediction_id="PRD-20260916-502",
        device_id="DB-01",
        risk_score=52.0,
        predicted_category="SUSPICIOUS_QUERY_VOLUME"
    )
    print(f"    Action Recommended: {rec_sec.recommendedAction.value}")
    print(f"    Priority          : {rec_sec.priority.value}")

    assert rec_sec.recommendedAction == ResponseActionType.INCREASE_SECURITY_LEVEL
    assert rec_sec.priority == RecommendationPriorityEnum.MEDIUM
    print("    [PASS] Moderate anomaly mapped to INCREASE_SECURITY_LEVEL.")

    # 6. Baseline Anomaly -> MARK_DEVICE_AT_RISK
    print("\n[6/9] Auditing Baseline Anomaly -> MARK_DEVICE_AT_RISK...")
    rec_risk = response_recommendation_engine.formulate_recommendation(
        alert_id="ALT-20260916-601",
        prediction_id="PRD-20260916-602",
        device_id="DNS-SERVER-01",
        risk_score=32.0,
        predicted_category="DNS_LOOKUP_SPIKE"
    )
    print(f"    Action Recommended: {rec_risk.recommendedAction.value}")
    print(f"    Priority          : {rec_risk.priority.value}")

    assert rec_risk.recommendedAction == ResponseActionType.MARK_DEVICE_AT_RISK
    assert rec_risk.priority == RecommendationPriorityEnum.LOW
    print("    [PASS] Baseline deviation mapped to MARK_DEVICE_AT_RISK.")

    # 7. Explainable Evidence Assembly (Non-Decorative XAI)
    print("\n[7/9] Auditing Explainable Evidence Assembly...")
    print(f"    Total Evidence Items: {len(rec_isolate.evidence)}")
    for ev in rec_isolate.evidence:
        print(f"      - {ev}")

    assert len(rec_isolate.evidence) >= 4
    assert any("XAI Driver:" in ev for ev in rec_isolate.evidence)
    print("    [PASS] SHAP feature drivers retained directly inside evidence array.")

    # 8. Recommendation Status Lifecycle
    print("\n[8/9] Auditing Recommendation Status Lifecycle...")
    rid = rec_isolate.recommendationId
    assert rec_isolate.status == RecommendationStatusEnum.PENDING

    appr = response_recommendation_engine.transition_status(rid, RecommendationStatusEnum.APPROVED_FOR_SIMULATION)
    print(f"    Status Transition: PENDING -> {appr.status.value}")
    assert appr.status == RecommendationStatusEnum.APPROVED_FOR_SIMULATION

    execd = response_recommendation_engine.transition_status(rid, RecommendationStatusEnum.EXECUTED)
    print(f"    Status Transition: APPROVED -> {execd.status.value}")
    assert execd.status == RecommendationStatusEnum.EXECUTED
    print("    [PASS] Recommendation lifecycle transitions verified.")

    # 9. Pending Queue Filtering
    print("\n[9/9] Auditing Pending Queue Filtering...")
    pending_list = response_recommendation_engine.get_pending_recommendations()
    print(f"    Remaining Pending Recommendations: {len(pending_list)}")
    assert rid not in [p.recommendationId for p in pending_list]
    print("    [PASS] Executed recommendations filtered out from pending queue.")

    print("\n" + "=" * 80)
    print("       ALL DAY 171 RESPONSE RECOMMENDATION ENGINE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day171_suite()