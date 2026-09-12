import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.prediction.prediction_models import (
    AttackPrediction, ThreatClassEnum, PredictedAttackCategory,
    RiskLevelEnum, PredictionStatusEnum
)
from services.digital_twin.ml.risk.risk_synthesizer import risk_synthesizer
from services.digital_twin.ml.prediction.attack_prediction_engine import attack_prediction_engine

def run_day106_suite():
    print("=" * 80)
    print("       WEEK 16 - DAY 106: ADVANCED ATTACK PREDICTION ARCHITECTURE AUDIT")
    print("=" * 80 + "\n")

    attack_prediction_engine.clear()

    # 1. Threat Probability vs Category Confidence Decoupling Audit
    print("[1/6] Auditing Decoupling of Threat Probability vs Category Confidence...")
    pred_dos = attack_prediction_engine.generate_prediction(
        features={"packet_rate": 350.0, "bytes_per_second": 250000.0},
        source="10.0.0.99",
        destination="10.0.0.1",
        device_id="CORE-ROUTER",
        device_criticality=0.9,
        network_exposure=0.8,
        binary_threat_prob=0.87,
        multiclass_probabilities={"DOS_LIKE": 0.91, "EXFILTRATION_LIKE": 0.09}
    )

    print(f"    Threat Probability  : {pred_dos.threatProbability} ({pred_dos.threatProbability * 100:.1f}%)")
    print(f"    Predicted Category  : {pred_dos.predictedCategory.value}")
    print(f"    Category Confidence : {pred_dos.categoryConfidence} ({pred_dos.categoryConfidence * 100:.1f}%)")
    print(f"    Risk Score          : {pred_dos.riskScore}")
    print(f"    Risk Level          : {pred_dos.riskLevel.value}")
    print(f"    Prediction Status   : {pred_dos.predictionStatus.value}")

    assert pred_dos.threatProbability == 0.87
    assert pred_dos.categoryConfidence == 0.91
    assert pred_dos.threatProbability != pred_dos.categoryConfidence
    assert pred_dos.predictedCategory == PredictedAttackCategory.DOS_LIKE
    assert pred_dos.threatClass == ThreatClassEnum.THREAT
    print("    [PASS] Threat Probability and Category Confidence decoupled and validated.")

    # 2. Contextual Risk Synthesizer Range & Level Mapping
    print("\n[2/6] Auditing Contextual Risk Formulation and Severity Mapping...")
    # Benign observation
    score_low, lvl_low, _ = risk_synthesizer.calculate_risk(0.05, PredictedAttackCategory.NORMAL, 0.99)
    assert lvl_low == RiskLevelEnum.LOW
    assert score_low < 30.0

    # High threat + critical infrastructure asset
    score_crit, lvl_crit, _ = risk_synthesizer.calculate_risk(
        threat_prob=0.95,
        category=PredictedAttackCategory.EXFILTRATION_LIKE,
        confidence=0.92,
        device_criticality=1.0,
        network_exposure=1.0
    )
    print(f"    Benign Risk Score: {score_low} -> {lvl_low.value}")
    print(f"    Exfiltration Critical Risk Score: {score_crit} -> {lvl_crit.value}")
    assert lvl_crit == RiskLevelEnum.CRITICAL
    assert score_crit >= 85.0
    print("    [PASS] Contextual risk engine maps benign to LOW and critical exfiltration to CRITICAL.")

    # 3. Prediction Lifecycle State Machine (HIGH vs LOW Confidence)
    print("\n[3/6] Auditing Prediction Lifecycle State Machine...")
    pred_low_conf = attack_prediction_engine.generate_prediction(
        features={"packet_rate": 60.0},
        source="10.0.0.12",
        destination="10.0.0.5",
        binary_threat_prob=0.70,
        multiclass_probabilities={"PORT_SCAN": 0.55, "DOS_LIKE": 0.45}
    )
    assert pred_low_conf.predictionStatus == PredictionStatusEnum.LOW_CONFIDENCE
    assert pred_dos.predictionStatus == PredictionStatusEnum.HIGH_CONFIDENCE
    print(f"    High Conf Prediction Status: {pred_dos.predictionStatus.value} (Conf: {pred_dos.categoryConfidence})")
    print(f"    Marginal Prediction Status : {pred_low_conf.predictionStatus.value} (Conf: {pred_low_conf.categoryConfidence})")
    print("    [PASS] State machine discriminates HIGH_CONFIDENCE (>=0.80) from LOW_CONFIDENCE (<0.80).")

    # 4. Canonical Attack Category Taxonomy
    print("\n[4/6] Auditing Canonical Category Taxonomy Coverage...")
    expected_categories = {
        "NORMAL", "PORT_SCAN", "BRUTE_FORCE_LIKE", "DOS_LIKE", "DNS_ANOMALY",
        "BEACONING", "LATERAL_MOVEMENT_LIKE", "EXFILTRATION_LIKE", "NETWORK_INTRUSION"
    }
    registered_categories = {c.value for c in PredictedAttackCategory}
    assert expected_categories == registered_categories
    print(f"    [PASS] All {len(registered_categories)} canonical attack categories validated.")

    # 5. Evidence Extraction Lineage
    print("\n[5/6] Auditing Evidence and Explainability Payload...")
    ev = pred_dos.evidence
    print(f"    Top Contributing Features : {ev.topContributingFeatures}")
    print(f"    Feature Values Captured    : {ev.featureValues}")
    print(f"    Rationale                  : {ev.rationale}")

    assert len(ev.topContributingFeatures) > 0
    assert "bytes_per_second" in ev.featureValues or "packet_rate" in ev.featureValues
    print("    [PASS] Explainable evidence lineage verified.")

    # 6. Formatted Summary Dictionary Audit
    print("\n[6/6] Auditing Formatted Dashboard Output Serialization...")
    summary = pred_dos.to_summary_dict()
    print(f"    Summary Output: {summary}")

    assert summary["threatProbability"] == "87.0%"
    assert summary["categoryConfidence"] == "91.0%"
    assert summary["predictedCategory"] == "DOS_LIKE"
    assert summary["riskLevel"] == "CRITICAL"
    print("    [PASS] Formatted percentages and categorical summary strings match specifications.")

    print("\n" + "=" * 80)
    print("       ALL DAY 106 PREDICTION ARCHITECTURE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day106_suite()