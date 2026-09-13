import sys
import json
from pathlib import Path
import joblib

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.xai.explanations.xai_models import (
    ExplanationStatusEnum, FeatureAttribution, PredictionExplanation
)
from services.digital_twin.ml.xai.xai_engine import base_xai_engine
from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES

def run_day120_suite():
    print("=" * 80)
    print("       WEEK 18 - DAY 120: EXPLAINABLE AI ARCHITECTURE AUDIT")
    print("=" * 80 + "\n")

    base_xai_engine.clear()

    # 1. XAI Module Loading & Schema Validation
    print("[1/8] Auditing XAI Module and Schema Instantiation...")
    assert base_xai_engine is not None
    assert ExplanationStatusEnum.GENERATED.value == "GENERATED"
    print("    [PASS] XAI Engine and Schema contracts verified.")

    # 2. Model Loading & Global Feature Importance Extraction (Level 1)
    print("\n[2/8] Auditing Trained Model Loading and Global Feature Importance Extraction...")
    rf_path = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "random_forest" / "model.joblib"
    assert rf_path.exists(), f"Baseline model artifact not found at {rf_path}"

    loaded_data = joblib.load(rf_path)
    model = loaded_data["model"] if isinstance(loaded_data, dict) and "model" in loaded_data else loaded_data

    global_imp = base_xai_engine.extract_global_feature_importance(model, feature_names=FEATURE_NAMES)
    print(f"    Total Evaluated Global Features: {len(global_imp)}")
    top_3_global = list(global_imp.items())[:3]
    for fn, imp in top_3_global:
        print(f"      * {fn:<28} : Importance = {imp:.4f}")

    assert len(global_imp) == len(FEATURE_NAMES)
    assert all(0.0 <= v <= 1.0 for v in global_imp.values())
    print("    [PASS] Level 1 Global Feature Importances computed.")

    # 3. Local Feature Attribution Execution (Level 2)
    print("\n[3/8] Auditing Local Feature Attribution on Port Scan Telemetry...")
    port_scan_feats = {
        "packet_rate": 0.5,
        "bytes": 0.3,
        "connection_frequency": 3.1,
        "destination_diversity": 2.4,
        "unique_destination_ports": 2.8,
        "failed_connections": 1.9,
        "flow_duration": -0.5
    }

    explanation = base_xai_engine.explain_prediction(
        prediction_id="PRED-SCAN-001",
        feature_values=port_scan_feats,
        threat_probability=0.87,
        predicted_category="PORT_SCAN",
        category_confidence=0.91,
        risk_score=78.4,
        risk_level="HIGH",
        model=model,
        model_name="random_forest",
        model_version="rf-v1.0",
        feature_version="feature-v1.0"
    )

    # 4. Feature Names & Values Preservation
    print("\n[4/8] Auditing Feature Names and Ingress Values Preservation...")
    assert len(explanation.featureValues) == len(FEATURE_NAMES)
    assert explanation.featureValues["connection_frequency"] == 3.1
    assert explanation.featureValues["destination_diversity"] == 2.4
    print("    [PASS] Feature names and numeric values preserved without loss.")

    # 5. Prediction ID, Model Version, and Feature Version Lineage
    print("\n[5/8] Auditing Model and Feature Provenance Lineage...")
    print(f"    Explanation ID   : {explanation.explanationId}")
    print(f"    Prediction ID    : {explanation.predictionId}")
    print(f"    Model Name       : {explanation.modelName}")
    print(f"    Model Version    : {explanation.modelVersion}")
    print(f"    Feature Version  : {explanation.featureVersion}")

    assert explanation.predictionId == "PRED-SCAN-001"
    assert explanation.modelName == "random_forest"
    assert explanation.modelVersion == "rf-v1.0"
    assert explanation.featureVersion == "feature-v1.0"
    print("    [PASS] Complete prediction provenance validated.")

    # 6. Directional Feature Attribution Audit
    print("\n[6/8] Auditing Directional Feature Attributions (+ / -)...")
    print("    Top Positive Escalating Contributors:")
    for attr in explanation.topPositiveFeatures[:3]:
        print(f"      + {attr.featureName:<28} : {attr.contributionFormatted} (Val: {attr.featureValue})")
        assert attr.contribution >= 0.0

    print("    Top Negative Mitigating Features:")
    for attr in explanation.topNegativeFeatures[:2]:
        print(f"      - {attr.featureName:<28} : {attr.contributionFormatted} (Val: {attr.featureValue})")
        assert attr.contribution <= 0.0

    assert len(explanation.topPositiveFeatures) > 0
    print("    [PASS] Positive and Negative attributions correctly categorized.")

    # 7. Level 3 Evidence & Natural Language Synthesis Audit
    print("\n[7/8] Auditing Level 3 Natural Language Explanation...")
    print("    Synthesized Evidence Items:")
    for ev in explanation.evidence:
        print(f"      * {ev}")
    print(f"\n    Analyst Narrative:\n    > \"{explanation.naturalLanguageExplanation}\"")

    assert len(explanation.evidence) > 0
    assert "PORT_SCAN" in explanation.naturalLanguageExplanation
    assert "threat probability" in explanation.naturalLanguageExplanation.lower()
    print("    [PASS] Human-readable reasoning successfully synthesized.")

    # 8. Explanation Status & Disk Artifact Verification
    print("\n[8/8] Auditing Explanation Status and Artifact Persistence...")
    assert explanation.explanationStatus == ExplanationStatusEnum.GENERATED
    print(f"    Explanation Status: {explanation.explanationStatus.value}")

    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai" / "prediction_explanations.json"
    assert out_file.exists(), "prediction_explanations.json was not created on disk."

    with open(out_file, "r", encoding="utf-8") as f:
        stored = json.load(f)
    assert len(stored) >= 1
    assert stored[-1]["explanationId"] == explanation.explanationId
    print(f"    Persisted Explanations Count: {len(stored)}")
    print("    [PASS] Valid explanation written and verified in prediction_explanations.json.")

    print("\n" + "=" * 80)
    print("       ALL DAY 120 EXPLAINABLE AI ARCHITECTURE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day120_suite()