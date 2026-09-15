import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.predictions.prediction_models import (
    AttackCategoryEnum, LivePredictionDetail
)
from frontend.predictions.prediction_panel_engine import prediction_panel_engine

def run_day147_suite():
    print("=" * 80)
    print("       WEEK 21 - DAY 147: PREDICTIONS PANEL & XAI INTEGRATION AUDIT")
    print("=" * 80 + "\n")

    # 1. Prediction Display & Panel Rendering
    print("[1/9] Auditing Prediction Panel CLI Layout & Card Fields...")
    pred = prediction_panel_engine.get_live_prediction("WEB-01")
    panel_str = pred.render_cli_panel()
    print(panel_str)

    assert pred.targetDevice == "WEB-01"
    assert pred.predictedCategory == AttackCategoryEnum.PORT_SCAN
    assert pred.confidenceScore == 0.91
    assert pred.riskLevel == RiskLevelTier.HIGH
    print("    [PASS] Prediction panel rendered with complete attributes.")

    # 2. Current vs Future Probability (Dual Horizon)
    print("\n[2/9] Auditing Dual Horizon Tracking (Current vs Future)...")
    print(f"    Current Threat (Now) : {pred.currentThreatProbability*100:.1f}%")
    print(f"    Future Threat  (60s) : {pred.futureThreatProbability*100:.1f}%")

    assert pred.currentThreatProbability == 0.72
    assert pred.futureThreatProbability == 0.87
    assert pred.currentThreatProbability != pred.futureThreatProbability
    print("    [PASS] Current and Future threat probabilities maintained distinctly.")

    # 3. Model & Feature Provenance Metadata
    print("\n[3/9] Auditing Model & Feature Version Metadata...")
    m = pred.modelInfo
    print(f"    Classifier       : {m.modelName} ({m.modelVersion})")
    print(f"    Feature Pipeline : {m.featureVersion}")
    print(f"    Forecaster       : {m.timeSeriesModel} (Horizon: {m.predictionHorizonSec}s)")

    assert m.modelName == "Random Forest"
    assert m.modelVersion == "model-v1.2"
    assert m.timeSeriesModel == "LSTM"
    print("    [PASS] Model and feature provenance verified.")

    # 4. Attack Category Enum Coverage
    print("\n[4/9] Auditing Attack Category Enums...")
    expected_categories = [
        "NORMAL", "PORT_SCAN", "BRUTE_FORCE_LIKE", "DOS_LIKE",
        "DNS_ANOMALY", "BEACONING", "LATERAL_MOVEMENT_LIKE", "EXFILTRATION_LIKE"
    ]
    for ec in expected_categories:
        assert hasattr(AttackCategoryEnum, ec)
        print(f"    Category Supported: {ec:<24} | Valid: OK")
    print("    [PASS] All 8 canonical attack categories supported.")

    # 5. SHAP Feature Attribution Values & Waterfall Signs
    print("\n[5/9] Auditing SHAP Feature Attributions...")
    shaps = pred.shapContributions
    print(f"    Total Evaluated Features: {len(shaps)}")
    for s in shaps:
        print(f"      * {s.featureName:<24} SHAP: {s.shapValue:+0.2f} [{s.direction}]")

    assert len(shaps) >= 6
    assert any(s.shapValue > 0 for s in shaps)
    assert any(s.shapValue < 0 for s in shaps)  # Negative contributor present
    print("    [PASS] Positive and negative SHAP attribution values verified.")

    # 6. Feature Ranking by Relative Importance
    print("\n[6/9] Auditing Feature Attribution Ranking...")
    top_feature = shaps[0]
    print(f"    Top Contributing Feature: {top_feature.featureName} ({top_feature.shapValue:+0.2f})")
    assert top_feature.featureName == "connection_frequency"
    assert abs(shaps[0].shapValue) >= abs(shaps[1].shapValue)
    print("    [PASS] Features ranked in descending order of attribution weight.")

    # 7. Human-Readable Explanation Generation
    print("\n[7/9] Auditing Human-Readable Reasoning Synthesis...")
    print(f"    Summary: {pred.shortExplanation}")
    print("    Detailed Breakdown:")
    for d in pred.detailedExplanation:
        print(f"      - {d}")

    assert "connection frequency" in pred.shortExplanation.lower()
    assert len(pred.detailedExplanation) >= 3
    print("    [PASS] Plain-language explanatory narratives verified.")

    # 8. Missing XAI Data Graceful Handling
    print("\n[8/9] Auditing Graceful Handling When XAI Data Is Missing...")
    fallback_pred = prediction_panel_engine.generate_prediction_with_xai(
        target_device="CLIENT-01",
        current_prob=0.55,
        future_prob=0.65,
        category=AttackCategoryEnum.DNS_ANOMALY,
        confidence=0.89,
        shap_values=None  # Missing SHAP
    )
    print(f"    Fallback Contributions Count: {len(fallback_pred.shapContributions)}")
    assert len(fallback_pred.shapContributions) > 0
    assert fallback_pred.shapContributions[0].featureName == "baseline_deviations"
    print("    [PASS] System degraded gracefully with structured baseline attributions.")

    # 9. Invalid Prediction Defensive Validation
    print("\n[9/9] Auditing Defensive Validation on Out-of-Bounds Probabilities...")
    invalid_caught = False
    try:
        prediction_panel_engine.generate_prediction_with_xai(
            target_device="WEB-01",
            current_prob=1.85,  # Invalid
            future_prob=0.50,
            category=AttackCategoryEnum.PORT_SCAN,
            confidence=0.90
        )
    except ValueError as e:
        invalid_caught = True
        print(f"    Trapped Out-of-Bounds Probability: {e}")
    assert invalid_caught
    print("    [PASS] Out-of-bounds probability rejected defensively.")

    # Reset environment
    prediction_panel_engine._seed_default_prediction()

    print("\n" + "=" * 80)
    print("       ALL DAY 147 PREDICTION & XAI TESTS PASSED CLEANLY")
    print("       PHASE 18 (WEEK 21): DASHBOARD FOUNDATION GRADUATED")
    print("================================================================================")

if __name__ == "__main__":
    run_day147_suite()