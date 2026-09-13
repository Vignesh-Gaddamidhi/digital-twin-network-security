import sys
import json
from pathlib import Path
import numpy as np
import joblib

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import shap
from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES, dataset_loader
from services.digital_twin.ml.xai.shap.shap_models import ContributionDirection, SHAPExplanation
from services.digital_twin.ml.xai.shap.shap_engine import shap_explainer_engine

def run_day121_suite():
    print("=" * 80)
    print("       WEEK 18 - DAY 121: SHAP INTEGRATION & LOCAL EXPLANATIONS AUDIT")
    print("=" * 80 + "\n")

    shap_explainer_engine.clear()

    # 1. SHAP Module Load Test
    print("[1/9] Auditing SHAP Library Loading & Version...")
    assert shap is not None
    print(f"    SHAP Version: {shap.__version__}")
    print("    [PASS] SHAP framework imported successfully.")

    # 2. Model Loading & Verification
    print("\n[2/9] Auditing Baseline Model Loading...")
    rf_path = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "random_forest" / "model.joblib"
    assert rf_path.exists()
    model_data = joblib.load(rf_path)
    model = model_data["model"] if isinstance(model_data, dict) and "model" in model_data else model_data
    assert hasattr(model, "predict_proba")
    print("    [PASS] Random Forest model loaded from disk.")

    # 3. Model Prediction Success
    print("\n[3/9] Auditing Model Prediction on Port Scan Telemetry...")
    test_input = {
        "packet_rate": 0.65,
        "bytes": 0.40,
        "connection_frequency": 3.8,
        "destination_diversity": 2.9,
        "unique_destination_ports": 3.4,
        "failed_connections": 2.5,
        "flow_duration": -0.8,
        "dns_frequency": -0.5
    }
    feat_vec = np.array([[float(test_input.get(fn, 0.0)) for fn in FEATURE_NAMES]], dtype=np.float32)
    prob = float(model.predict_proba(feat_vec)[0, 1])
    print(f"    Raw Model Prediction (Threat Probability): {prob * 100:.1f}%")
    assert 0.0 <= prob <= 1.0
    print("    [PASS] Prediction succeeded.")

    # 4. SHAP Explanation Execution
    print("\n[4/9] Executing Model-Specific TreeExplainer for Prediction Instance...")
    pred_id = "PRED-PORT-SCAN-87"
    explanation = shap_explainer_engine.explain_instance(
        prediction_id=pred_id,
        features=test_input,
        model=model,
        model_name="random_forest",
        model_version="rf-v1.0"
    )
    assert explanation is not None
    print(f"    Explanation ID   : {explanation.explanationId}")
    print(f"    Base Value phi_0 : {explanation.baseValueFormatted}")
    print(f"    Output f(x)      : {explanation.predictionValueFormatted}")
    print("    [PASS] SHAP explanation generated.")

    # 5. Every Feature Has a Contribution
    print("\n[5/9] Auditing Feature Completeness (Every Feature Has a SHAP Attribution)...")
    assert len(explanation.features) == len(FEATURE_NAMES)
    feature_names_in_explanation = [f.featureName for f in explanation.features]
    assert set(feature_names_in_explanation) == set(FEATURE_NAMES)
    print(f"    Total Feature Attributions: {len(explanation.features)} (Expected: {len(FEATURE_NAMES)})")
    print("    [PASS] Every feature has an associated Shapley value.")

    # 6. Feature Values Match Input Exactly
    print("\n[6/9] Auditing Feature Values Match Input Telemetry...")
    for item in explanation.features:
        expected_val = round(float(test_input.get(item.featureName, 0.0)), 4)
        assert item.featureValue == expected_val
    assert next(f for f in explanation.features if f.featureName == "connection_frequency").featureValue == 3.8
    assert next(f for f in explanation.features if f.featureName == "destination_diversity").featureValue == 2.9
    print("    [PASS] Feature values match input telemetry with 100% fidelity.")

    # 7. Positive and Negative Contributions Identified
    print("\n[7/9] Auditing Positive (Threat) and Negative (Mitigating) Directional Contributions...")
    print("    Top Positive Contributors (Elevate Threat):")
    for pos in explanation.topPositiveFeatures[:4]:
        print(f"      + {pos.featureName:<28} : SHAP = {pos.shapValueFormatted} (Value: {pos.featureValue})")
        assert pos.shapValue > 0.0
        assert pos.direction == ContributionDirection.POSITIVE

    print("    Top Negative Contributors (Reduce Threat):")
    for neg in explanation.topNegativeFeatures[:3]:
        print(f"      - {neg.featureName:<28} : SHAP = {neg.shapValueFormatted} (Value: {neg.featureValue})")
        assert neg.shapValue < 0.0
        assert neg.direction == ContributionDirection.NEGATIVE

    assert len(explanation.topPositiveFeatures) > 0
    assert len(explanation.topNegativeFeatures) > 0
    print("    [PASS] Both positive and negative contributions identified.")

    # 8. Top Contributors Sorted Correctly by Absolute SHAP Value
    print("\n[8/9] Auditing Ranking & Sorting by Absolute Contribution...")
    for i in range(len(explanation.features) - 1):
        curr_item = explanation.features[i]
        next_item = explanation.features[i + 1]
        assert curr_item.absoluteContribution >= next_item.absoluteContribution
        assert curr_item.rank == i + 1

    print(f"    #1 Highest Impact Feature: {explanation.features[0].featureName} (|phi| = {explanation.features[0].absoluteContribution})")
    print(f"    #2 Highest Impact Feature: {explanation.features[1].featureName} (|phi| = {explanation.features[1].absoluteContribution})")
    print("    [PASS] Strict descending monotonic sort by absolute contribution verified.")

    # 9. Linkage to Prediction ID and Artifact Persistence
    print("\n[9/9] Auditing Prediction ID Linkage and Persistence...")
    assert explanation.predictionId == pred_id

    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai" / "shap_explanations.json"
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        stored = json.load(f)
    assert len(stored) >= 1
    assert stored[-1]["predictionId"] == pred_id

    print(f"    Summary Output:\n{explanation.to_summary_string()}")
    print("    [PASS] Explanation linked to prediction ID and saved in shap_explanations.json.")

    print("\n" + "=" * 80)
    print("       ALL DAY 121 SHAP INTEGRATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day121_suite()