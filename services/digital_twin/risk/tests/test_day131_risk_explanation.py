import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.explanation.risk_explanation_models import (
    RiskConfidenceLevel, RISK_LEVEL_POLICIES
)
from services.digital_twin.risk.explanation.risk_explanation_engine import risk_explanation_engine

def run_day131_suite():
    print("=" * 80)
    print("       WEEK 19 - DAY 131: RISK LEVELS, EXPLANATION & XAI INTEGRATION AUDIT")
    print("=" * 80 + "\n")

    risk_explanation_engine.clear()

    # 1. Four Risk Levels Policy Verification
    print("[1/8] Auditing Four Risk Level Policies & Workflow Playbooks...")
    assert len(RISK_LEVEL_POLICIES) == 4
    for tier in [RiskLevelTier.LOW, RiskLevelTier.MEDIUM, RiskLevelTier.HIGH, RiskLevelTier.CRITICAL]:
        policy = RISK_LEVEL_POLICIES[tier]
        print(f"    Tier: {tier.value:<8} | Bounds: [{policy.minimumScore:4.1f}, {policy.maximumScore:5.1f}] | Action: {policy.recommendedAction[:50]}...")
        assert policy.description != ""
        assert policy.recommendedAction != ""

    print("    [PASS] All four risk tiers and action policies validated.")

    # 2. Boundary Classification Audit
    print("\n[2/8] Auditing Threshold Boundary Classifications...")
    from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
    assert threshold_classifier.classify(24.9) == RiskLevelTier.LOW
    assert threshold_classifier.classify(25.0) == RiskLevelTier.MEDIUM
    assert threshold_classifier.classify(49.9) == RiskLevelTier.MEDIUM
    assert threshold_classifier.classify(50.0) == RiskLevelTier.HIGH
    assert threshold_classifier.classify(74.9) == RiskLevelTier.HIGH
    assert threshold_classifier.classify(75.0) == RiskLevelTier.CRITICAL
    print("    [PASS] Strict threshold boundaries confirmed.")

    # 3. Dual Explanation Synthesis & SHAP Integration (Canonical Specification Case)
    print("\n[3/8] Auditing Dual Explanation Synthesis (Threat vs Risk)...")
    shap_features = ["connection frequency", "destination diversity", "abnormal port activity", "failed connections"]
    exp_canon = risk_explanation_engine.generate_risk_explanation(
        risk_id="RISK-CANON-131",
        prediction_id="PRED-CANON-131",
        device_id="DB-01",
        threat_probability=0.87,
        asset_criticality_level="CRITICAL",
        asset_criticality_weight=1.00,
        vulnerability_severity_level="HIGH",
        vulnerability_weight=0.80,
        attack_impact_level="CRITICAL",
        attack_impact_weight=1.00,
        risk_score=69.60,
        xai_contributing_features=shap_features
    )

    print(f"\n    Model Explanation (Why Predicted):\n    > {exp_canon.threatExplanation}")
    print(f"\n    Risk Explanation (Why Risky):\n    > {exp_canon.riskExplanation}")

    assert "connection frequency" in exp_canon.threatExplanation
    assert "destination diversity" in exp_canon.threatExplanation
    assert "Risk is HIGH" in exp_canon.riskExplanation
    assert "CRITICAL" in exp_canon.riskExplanation
    print("    [PASS] Dual explanation dimensions synthesized cleanly.")

    # 4. Factor Breakdown Validation
    print("\n[4/8] Auditing Risk Factor Breakdown Payload...")
    bd = exp_canon.factorBreakdown
    print(f"    Threat Probability : {bd['threatProbability']}")
    print(f"    Asset Criticality  : {bd['assetCriticality']}")
    print(f"    Vulnerability      : {bd['vulnerability']}")
    print(f"    Attack Impact      : {bd['attackImpact']}")
    print(f"    Calculated Risk    : {bd['calculatedRisk']}")
    print(f"    Risk Level         : {bd['riskLevel']}")

    assert bd["threatProbability"] == "87.0%"
    assert "CRITICAL" in bd["assetCriticality"]
    assert "HIGH" in bd["vulnerability"]
    assert "CRITICAL" in bd["attackImpact"]
    assert "69.60" in bd["calculatedRisk"]
    print("    [PASS] Complete factor breakdown verified.")

    # 5. Risk Assessment Confidence Audit
    print("\n[5/8] Auditing Risk Assessment Confidence Evaluation...")
    assert exp_canon.riskAssessmentConfidence == RiskConfidenceLevel.HIGH
    conf_partial = risk_explanation_engine.evaluate_risk_confidence(
        has_prediction=True, has_asset=True, has_vulnerability=False, has_impact=True
    )
    assert conf_partial == RiskConfidenceLevel.MEDIUM
    conf_low = risk_explanation_engine.evaluate_risk_confidence(
        has_prediction=True, has_asset=False, has_vulnerability=False, has_impact=False
    )
    assert conf_low == RiskConfidenceLevel.LOW
    print("    [PASS] Confidence correctly reflects completeness of environmental context.")

    # 6. Operational Limitations Disclaimer
    print("\n[6/8] Auditing Operational Limitations Disclaimer...")
    print(f"    Limitations: {exp_canon.limitations}")
    assert "does not constitute absolute proof" in exp_canon.limitations
    print("    [PASS] Limitations disclaimer verified verbatim.")

    # 7. Missing XAI Explanation Handling
    print("\n[7/8] Auditing Missing XAI Explanation Handling...")
    exp_missing = risk_explanation_engine.generate_risk_explanation(
        risk_id="RISK-MISSING",
        prediction_id="PRED-MISSING",
        device_id="WEB-01",
        threat_probability=0.45,
        asset_criticality_level="MEDIUM",
        asset_criticality_weight=0.60,
        vulnerability_severity_level="LOW",
        vulnerability_weight=0.40,
        attack_impact_level="LOW",
        attack_impact_weight=0.40,
        risk_score=4.32,
        xai_threat_explanation=None,
        xai_contributing_features=None
    )
    print(f"    Fallback Threat Explanation: {exp_missing.threatExplanation}")
    assert "45.0%" in exp_missing.threatExplanation
    assert exp_missing.riskLevel == RiskLevelTier.LOW
    print("    [PASS] Missing XAI inputs handled gracefully with fallback factual description.")

    # 8. Partial XAI Explanation Handling
    print("\n[8/8] Auditing Partial XAI Explanation Handling...")
    exp_partial = risk_explanation_engine.generate_risk_explanation(
        risk_id="RISK-PARTIAL",
        prediction_id="PRED-PARTIAL",
        device_id="CLIENT-01",
        threat_probability=0.75,
        asset_criticality_level="LOW",
        asset_criticality_weight=0.40,
        vulnerability_severity_level="LOW",
        vulnerability_weight=0.40,
        attack_impact_level="LOW",
        attack_impact_weight=0.40,
        risk_score=4.80,
        is_partial_xai=True
    )
    print(f"    Partial Attribution Notice: {exp_partial.threatExplanation}")
    assert "partially available" in exp_partial.threatExplanation
    print("    [PASS] Partial XAI explanation gracefully handled.")

    # Verify Disk Artifact Persistence
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine" / "risk_explanations.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        stored = json.load(f)
    assert len(stored) >= 3
    assert stored[-1]["riskId"] == "RISK-PARTIAL"

    print("\n" + exp_canon.to_formatted_report())
    print("\n" + "=" * 80)
    print("       ALL DAY 131 RISK EXPLANATION & XAI TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day131_suite()