import sys
import json
from pathlib import Path
import joblib

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.xai.shap.shap_engine import shap_explainer_engine
from services.digital_twin.ml.xai.feature_importance.global_importance_engine import global_feature_importance_engine
from services.digital_twin.ml.xai.visualization.xai_dashboard_engine import xai_dashboard_engine
from services.digital_twin.ml.xai.visualization.dashboard_models import (
    EvidenceSeverityLevel, ComprehensiveXAIForensicReport
)

def run_day125_suite():
    print("=" * 80)
    print("       WEEK 18 - DAY 125: XAI VISUALIZATION, REPORTS & AUDIT TRAIL")
    print("=" * 80 + "\n")

    # 1. Load Baseline Model
    print("[1/10] Loading Trained Classifier Artifact...")
    rf_path = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "random_forest" / "model.joblib"
    assert rf_path.exists()
    model_data = joblib.load(rf_path)
    model = model_data["model"] if isinstance(model_data, dict) and "model" in model_data else model_data
    print("    [PASS] Model loaded successfully.")

    # Ingress Telemetry for Port-Scan Profile
    test_features = {
        "connection_frequency": 48.0,
        "destination_diversity": 2.4,
        "unique_destination_ports": 150.0,
        "failed_connections": 12.0,
        "packet_rate": 0.65,
        "bytes": 0.40,
        "dns_frequency": 0.5,
        "flow_duration": 5.0
    }
    pred_id = "PRED-VIS-DAY125"

    # 2. Local SHAP Explanation Generation
    print("\n[2/10] Computing Local SHAP Attributions for Visualization...")
    shap_exp = shap_explainer_engine.explain_instance(
        prediction_id=pred_id,
        features=test_features,
        model=model,
        model_name="random_forest",
        model_version="rf-v1.0"
    )
    assert shap_exp is not None
    print(f"    Base Value: {shap_exp.baseValueFormatted} -> Prediction: {shap_exp.predictionValueFormatted}")
    print("    [PASS] Local SHAP explanation generated.")

    # 3. Global Importance Baseline Initialization
    print("\n[3/10] Initializing Global Feature Importance Baseline...")
    _ = global_feature_importance_engine.generate_global_importance_report(
        model=model,
        model_name="random_forest",
        model_version="rf-v1.0"
    )
    print("    [PASS] Global feature importance baseline ready.")

    # 4. Generate Comprehensive Forensic Report
    print("\n[4/10] Generating Comprehensive Forensic XAI Report...")
    report = xai_dashboard_engine.generate_forensic_report(
        prediction_id=pred_id,
        features=test_features,
        shap_explanation=shap_exp,
        threat_probability=0.87,
        predicted_category="PORT_SCAN",
        category_confidence=0.91,
        risk_level="HIGH"
    )
    assert report is not None
    print(f"    Report ID: {report.reportId}")
    print("    [PASS] Forensic XAI report compiled successfully.")

    # 5. SHAP Visualization & Local Waterfall Bar Plot
    print("\n[5/10] Auditing Local Waterfall Visualization...")
    print(report.localWaterfallAscii)
    assert "█" in report.localWaterfallAscii
    assert "Base:" in report.localWaterfallAscii
    assert "Output:" in report.localWaterfallAscii
    print("    [PASS] Local waterfall chart formatted with bar blocks.")

    # 6. Global Summary Chart Verification
    print("\n[6/10] Auditing Global Feature Importance Chart Data...")
    print(report.globalSummaryAscii)
    assert "█" in report.globalSummaryAscii
    assert "Global SHAP" in report.globalSummaryAscii
    print("    [PASS] Global summary chart data validated.")

    # 7. Prediction Explanation Card Data
    print("\n[7/10] Auditing Prediction Explanation Card Payload...")
    card = report.cardData
    print(f"    Card ID            : {card.cardId}")
    print(f"    Threat Probability : {card.threatProbabilityFormatted}")
    print(f"    Predicted Category : {card.predictedCategory}")
    print(f"    Confidence         : {card.categoryConfidenceFormatted}")
    print(f"    Risk Level         : {card.riskLevel}")
    print(f"    Top Factor Badges  : {card.topFactorBadges}")

    assert card.threatProbabilityFormatted == "87.0%"
    assert card.predictedCategory == "PORT_SCAN"
    assert card.riskLevel == "HIGH"
    assert len(card.topFactorBadges) >= 2
    print("    [PASS] Dashboard explanation card payload validated.")

    # 8. Evidence Panel Data Audit
    print("\n[8/10] Auditing Evidence Panel Telemetry Grounding...")
    evidence = report.evidencePanel
    assert len(evidence) == len(test_features)
    sample_ev = next(e for e in evidence if e.featureName == "connection_frequency")
    print(f"    Sample Evidence Item: {sample_ev.featureLabel} = {sample_ev.observedValue} {sample_ev.unit} ({sample_ev.severity.value})")
    assert sample_ev.observedValue == 48.0
    assert sample_ev.severity in (EvidenceSeverityLevel.ELEVATED, EvidenceSeverityLevel.HIGH)
    print("    [PASS] Evidence panel values match actual telemetry with qualitative ratings.")

    # 9. Why-This-Prediction Panel Audit
    print("\n[9/10] Auditing Why-This-Prediction Directional Table...")
    why_items = report.whyThisPredictionPanel
    for item in why_items[:4]:
        print(f"    {item.directionIndicator} {item.featureLabel:<24} : {item.impactDescription} (SHAP: {item.shapFormatted})")
        assert item.directionIndicator in ("↑", "↓")
    print("    [PASS] Why-This-Prediction panel indicators validated.")

    # 10. Audit Trail, Versioning, and Cryptographic Reproducibility
    print("\n[10/10] Auditing Cryptographic Audit Trail & Reproducibility...")
    audit = report.auditTrail
    print(f"    Audit ID       : {audit.auditId}")
    print(f"    Prediction ID  : {audit.predictionId}")
    print(f"    Model Version  : {audit.modelVersion}")
    print(f"    Feature Version: {audit.featureVersion}")
    print(f"    Input Hash     : {audit.inputHash}")
    print(f"    SHAP Version   : {audit.shapVersion}")

    assert audit.predictionId == pred_id
    assert audit.modelVersion == "rf-v1.0"
    assert audit.featureVersion == "feature-v1.0"
    assert len(audit.inputHash) == 64  # SHA-256 hex digest length

    # Verify Reproducibility: Same input -> Same hash
    reproduced_hash = xai_dashboard_engine.calculate_input_hash(test_features, "rf-v1.0", "feature-v1.0")
    assert audit.inputHash == reproduced_hash

    # Verify Sensitivity: Altered input -> Different hash
    altered_feats = dict(test_features)
    altered_feats["connection_frequency"] = 49.0
    altered_hash = xai_dashboard_engine.calculate_input_hash(altered_feats, "rf-v1.0", "feature-v1.0")
    assert audit.inputHash != altered_hash
    print("    [PASS] Audit trail metadata and SHA-256 reproducibility confirmed.")

    # Verify Report Saved on Disk
    saved_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "xai" / "reports" / f"report_{pred_id}.json"
    assert saved_file.exists()
    print("    [PASS] Forensic report JSON verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 125 XAI VISUALIZATION & REPORT TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day125_suite()