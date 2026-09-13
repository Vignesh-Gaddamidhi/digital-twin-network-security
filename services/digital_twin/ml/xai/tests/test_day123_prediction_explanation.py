import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.xai.shap.shap_models import FeatureSHAPItem, ContributionDirection
from services.digital_twin.ml.xai.explanations.prediction_explanation_engine import prediction_explanation_engine
from services.digital_twin.ml.xai.explanations.enriched_explanation_models import EnrichedPredictionExplanation

def run_day123_suite():
    print("=" * 80)
    print("       WEEK 18 - DAY 123: PREDICTION EXPLANATION ENGINE AUDIT")
    print("=" * 80 + "\n")

    prediction_explanation_engine.clear()

    # 1. Canonical Port Scan SHAP Inputs (Day 123 Specification Example)
    print("[1/10] Constructing Canonical Specification Inputs (Threat Prob=0.87, PORT_SCAN, Risk=HIGH)...")
    shap_items = [
        FeatureSHAPItem(
            featureName="connection_frequency",
            featureValue=48.0,
            shapValue=0.31,
            shapValueFormatted="+0.3100",
            direction=ContributionDirection.POSITIVE,
            absoluteContribution=0.31,
            rank=1
        ),
        FeatureSHAPItem(
            featureName="destination_diversity",
            featureValue=2.4,
            shapValue=0.24,
            shapValueFormatted="+0.2400",
            direction=ContributionDirection.POSITIVE,
            absoluteContribution=0.24,
            rank=2
        ),
        FeatureSHAPItem(
            featureName="unique_destination_ports",
            featureValue=150.0,
            shapValue=0.18,
            shapValueFormatted="+0.1800",
            direction=ContributionDirection.POSITIVE,
            absoluteContribution=0.18,
            rank=3
        ),
        FeatureSHAPItem(
            featureName="failed_connections",
            featureValue=12.0,
            shapValue=0.09,
            shapValueFormatted="+0.0900",
            direction=ContributionDirection.POSITIVE,
            absoluteContribution=0.09,
            rank=4
        ),
        FeatureSHAPItem(
            featureName="flow_duration",
            featureValue=5.0,
            shapValue=-0.04,
            shapValueFormatted="-0.0400",
            direction=ContributionDirection.NEGATIVE,
            absoluteContribution=0.04,
            rank=5
        ),
        FeatureSHAPItem(
            featureName="dns_frequency",
            featureValue=0.5,
            shapValue=-0.02,
            shapValueFormatted="-0.0200",
            direction=ContributionDirection.NEGATIVE,
            absoluteContribution=0.02,
            rank=6
        )
    ]

    exp = prediction_explanation_engine.generate_explanation(
        prediction_id="PRED-PORT-SCAN-123",
        threat_probability=0.87,
        predicted_category="PORT_SCAN",
        category_confidence=0.91,
        risk_level="HIGH",
        shap_items=shap_items
    )

    # 1. Explanation Generated
    assert exp is not None
    assert exp.predictionId == "PRED-PORT-SCAN-123"
    print("    [PASS] Enriched explanation generated.")

    # 2. Actual Feature Values Used
    print("\n[2/10] Auditing Actual Feature Values in Evidence...")
    evidence_text = " ".join(exp.supportingEvidence)
    print(f"    Evidence snippet: {exp.supportingEvidence[0]}")
    assert "48.00" in evidence_text or "48.0" in evidence_text
    assert "2.40" in evidence_text or "2.4" in evidence_text
    print("    [PASS] Actual numeric feature values verified in evidence.")

    # 3. Actual SHAP Values Used
    print("\n[3/10] Auditing Actual SHAP Values in Technical Breakdown...")
    print(f"    Technical Breakdown:\n{exp.technicalExplanation}")
    assert "+0.3100" in exp.technicalExplanation or "+0.31" in exp.technicalExplanation
    assert "+0.2400" in exp.technicalExplanation or "+0.24" in exp.technicalExplanation
    assert "-0.0400" in exp.technicalExplanation or "-0.04" in exp.technicalExplanation
    print("    [PASS] Exact SHAP attribution values verified in technical output.")

    # 4. Positive Features Described
    print("\n[4/10] Auditing Positive Features Formulation...")
    assert len(exp.topPositiveContributors) == 4
    assert any("connection frequency" in s.lower() for s in exp.supportingEvidence)
    assert any("destination diversity" in s.lower() for s in exp.supportingEvidence)
    print("    [PASS] Threat-elevating drivers correctly described.")

    # 5. Negative Features Described
    print("\n[5/10] Auditing Negative Features Formulation...")
    assert len(exp.topNegativeContributors) == 2
    assert any("session duration" in s.lower() or "flow duration" in s.lower() for s in exp.supportingEvidence)
    assert any("dns" in s.lower() for s in exp.supportingEvidence)
    print("    [PASS] Mitigating baseline features correctly described.")

    # 6. No Fabricated Evidence Invariant
    print("\n[6/10] Auditing Strict Factual Invariant (Zero Hallucinated Claims)...")
    full_narrative = (exp.summary + " " + exp.detailedExplanation).lower()
    prohibited_hallucinations = ["500 machines", "scanned 500", "apt group", "malicious ip", "compromised password"]
    for ph in prohibited_hallucinations:
        assert ph not in full_narrative, f"Fabricated claim detected: {ph}"
    print("    [PASS] Factual integrity verified: zero hallucinated operational claims.")

    # 7. Short Explanation Works
    print("\n[7/10] Auditing Executive Short Summary...")
    print(f"    Short Summary: {exp.summary}")
    assert len(exp.summary) > 20
    assert "connection frequency" in exp.summary
    assert "destination diversity" in exp.summary
    print("    [PASS] Executive summary verified.")

    # 8. Detailed Explanation Works
    print("\n[8/10] Auditing Detailed Analyst Narrative...")
    print(f"    Detailed Narrative:\n    > {exp.detailedExplanation}")
    assert len(exp.detailedExplanation) > 50
    assert "connection frequency" in exp.detailedExplanation
    assert "destination-port" in exp.detailedExplanation or "destination diversity" in exp.detailedExplanation
    print("    [PASS] Detailed analyst narrative verified.")

    # 9. Technical Explanation Works
    print("\n[9/10] Auditing Technical Explanation...")
    assert "Top contributing features:" in exp.technicalExplanation
    assert "Top mitigating features:" in exp.technicalExplanation
    print("    [PASS] Technical breakdown verified.")

    # 10. Limitations Included
    print("\n[10/10] Auditing Epistemic Limitations & Disclaimers...")
    print(f"    Limitations: {exp.limitations}")
    expected_limit = "This explanation describes model behaviour and does not prove that an attack occurred."
    assert exp.limitations == expected_limit
    print("    [PASS] Model limitations disclaimer included verbatim.")

    # Persistence verification
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai" / "enriched_explanations.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        saved = json.load(f)
    assert len(saved) >= 1
    assert saved[-1]["predictionId"] == "PRED-PORT-SCAN-123"

    print("\n" + exp.to_formatted_display())
    print("\n" + "=" * 80)
    print("       ALL DAY 123 PREDICTION EXPLANATION ENGINE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day123_suite()