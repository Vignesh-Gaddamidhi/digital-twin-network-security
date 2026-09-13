import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.prediction.confidence.confidence_models import (
    ConfidenceTierEnum, ConfidenceThresholdConfig
)
from services.digital_twin.ml.prediction.confidence.confidence_engine import prediction_confidence_engine
from services.digital_twin.ml.prediction.calibration.calibration_engine import probability_calibration_engine
from services.digital_twin.ml.models.random_forest.random_forest_classifier import AttackRandomForestClassifier
from services.digital_twin.ml.training.dataset_loader import dataset_loader

def run_day109_suite():
    print("=" * 80)
    print("       WEEK 16 - DAY 109: CONFIDENCE & PROBABILITY CALIBRATION AUDIT")
    print("=" * 80 + "\n")

    # 1. Threat Probability vs Category Confidence Decoupling
    print("[1/6] Auditing Decoupled Threat Probability (87%) vs Category Confidence (91%)...")
    threat_prob = 0.87
    cat_dist = {
        "PORT_SCAN": 0.91,
        "DOS_LIKE": 0.05,
        "DNS_ANOMALY": 0.02,
        "NORMAL": 0.02
    }
    report_high = prediction_confidence_engine.evaluate_confidence(cat_dist)

    print(f"    Threat Probability  : {threat_prob * 100:.1f}%")
    print(f"    Predicted Category  : {report_high.topCategory} ({report_high.categoryConfidence * 100:.1f}%)")
    print(f"    Confidence Tier     : {report_high.confidenceTier.value}")
    print(f"    Separation Margin   : {report_high.separationMargin}")
    print(f"    Normalized Entropy  : {report_high.normalizedEntropy}")

    assert threat_prob == 0.87
    assert report_high.categoryConfidence == 0.91
    assert report_high.confidenceTier == ConfidenceTierEnum.HIGH_CONFIDENCE
    assert report_high.isLowConfidenceWarning is False
    print("    [PASS] Decoupled quantities and high-confidence state verified.")

    # 2. Low-Confidence Multi-Way Tie Safeguard
    print("\n[2/6] Auditing Low-Confidence Ambiguity Detection (Flat Distribution)...")
    ambiguous_dist = {
        "PORT_SCAN": 0.38,
        "DOS_LIKE": 0.31,
        "DNS_ANOMALY": 0.21,
        "BEACONING": 0.10
    }
    report_low = prediction_confidence_engine.evaluate_confidence(ambiguous_dist)

    print(f"    Top Category        : {report_low.topCategory} ({report_low.categoryConfidence * 100:.1f}%)")
    print(f"    Runner Up Category  : {report_low.runnerUpCategory}")
    print(f"    Separation Margin   : {report_low.separationMargin}")
    print(f"    Confidence Tier     : {report_low.confidenceTier.value}")
    print(f"    Warning Flag        : {report_low.isLowConfidenceWarning}")

    assert report_low.confidenceTier == ConfidenceTierEnum.LOW_CONFIDENCE
    assert report_low.isLowConfidenceWarning is True
    assert report_low.separationMargin < 0.15
    print("    [PASS] Ambiguous prediction safely gated to LOW_CONFIDENCE.")

    # 3. Normalized Shannon Entropy Properties
    print("\n[3/6] Auditing Shannon Entropy Uncertainty Metric...")
    # Perfectly certain: [1.0, 0.0, 0.0, 0.0]
    ent_zero = prediction_confidence_engine.calculate_normalized_entropy([1.0, 0.0, 0.0, 0.0])
    # Completely uniform: [0.25, 0.25, 0.25, 0.25]
    ent_max = prediction_confidence_engine.calculate_normalized_entropy([0.25, 0.25, 0.25, 0.25])

    print(f"    Entropy for Decisive Distribution: {ent_zero}")
    print(f"    Entropy for Uniform Guessing     : {ent_max}")
    assert ent_zero == 0.0
    assert ent_max == 1.0
    print("    [PASS] Entropy bounds [0.0, 1.0] verified.")

    # 4. Configurable Threshold Flexibility
    print("\n[4/6] Auditing Configurable Confidence Thresholds...")
    custom_cfg = ConfidenceThresholdConfig(
        highConfidenceThreshold=0.95,  # Stricter high confidence threshold
        highSeparationMargin=0.50
    )
    custom_engine = prediction_confidence_engine.__class__(config=custom_cfg)
    strict_report = custom_engine.evaluate_confidence(cat_dist)  # Top prob is 0.91 < 0.95

    assert strict_report.confidenceTier != ConfidenceTierEnum.HIGH_CONFIDENCE
    print(f"    Tier under strict 95% threshold: {strict_report.confidenceTier.value}")
    print("    [PASS] Threshold configuration is dynamically adjustable.")

    # 5. Probability Calibration Audit (Brier Score & ECE)
    print("\n[5/6] Auditing Probability Calibration on Baseline Classifier...")
    X_tr, y_tr, X_te, y_te, feats = dataset_loader.load_train_test()

    rf = AttackRandomForestClassifier(random_seed=42)
    rf.train(X_tr, y_tr, feature_names=feats)

    cal_rep = probability_calibration_engine.fit_and_audit_calibration(rf.model, X_te, y_te, method="sigmoid")

    print(f"    Raw Brier Score        : {cal_rep['rawMetrics']['brierScore']}")
    print(f"    Calibrated Brier Score : {cal_rep['calibratedMetrics']['brierScore']}")
    print(f"    Raw ECE Error          : {cal_rep['rawMetrics']['expectedCalibrationError']}")
    print(f"    Calibrated ECE Error   : {cal_rep['calibratedMetrics']['expectedCalibrationError']}")
    print(f"    Reliability Improved   : {cal_rep['isReliabilityImproved']}")

    assert "brierScore" in cal_rep["calibratedMetrics"]
    assert "expectedCalibrationError" in cal_rep["calibratedMetrics"]
    assert cal_rep["calibratedMetrics"]["brierScore"] <= 0.25
    print("    [PASS] Empirical calibration executed and evaluated.")

    # 6. Artifact Storage Verification
    print("\n[6/6] Auditing Calibration Artifact Persistence to Disk...")
    art_dir = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "calibration"
    assert (art_dir / "calibrator_sigmoid.joblib").exists()
    assert (art_dir / "calibration_report.json").exists()

    with open(art_dir / "calibration_report.json", "r", encoding="utf-8") as f:
        saved_data = json.load(f)
    assert saved_data["method"] == "sigmoid"
    print("    [PASS] Calibrator artifact and audit report verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 109 CONFIDENCE & CALIBRATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day109_suite()