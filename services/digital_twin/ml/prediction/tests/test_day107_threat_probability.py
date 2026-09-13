import sys
import json
import math
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.prediction.probability.threat_probability_engine import threat_probability_engine
from services.digital_twin.ml.prediction.probability.probability_models import ThreatClassEnum
from services.digital_twin.ml.models.random_forest.random_forest_classifier import AttackRandomForestClassifier
from services.digital_twin.ml.models.logistic_regression.logistic_regression_classifier import AttackLogisticRegressionClassifier
from services.digital_twin.ml.models.svm.svm_classifier import AttackSVMClassifier
from services.digital_twin.ml.models.xgboost.xgboost_classifier import AttackXGBoostClassifier

def run_day107_suite():
    print("=" * 80)
    print("       WEEK 16 - DAY 107: THREAT PROBABILITY ENGINE AUDIT")
    print("=" * 80 + "\n")

    threat_probability_engine.clear()

    # 1. Probability Validation Invariants
    print("[1/5] Auditing Strict Probability Validation Invariants...")
    assert threat_probability_engine.validate_probability(0.87) == 0.87
    assert threat_probability_engine.validate_probability(0.0) == 0.0
    assert threat_probability_engine.validate_probability(1.0) == 1.0

    # Negative bounds test
    try:
        threat_probability_engine.validate_probability(-0.2)
        assert False, "Failed to reject negative probability!"
    except ValueError:
        print("    [PASS] Correctly rejected negative probability (-0.2).")

    # Upper bounds test
    try:
        threat_probability_engine.validate_probability(1.5)
        assert False, "Failed to reject probability > 1.0!"
    except ValueError:
        print("    [PASS] Correctly rejected probability > 1.0 (1.5).")

    # NaN test
    try:
        threat_probability_engine.validate_probability(float("nan"))
        assert False, "Failed to reject NaN probability!"
    except ValueError:
        print("    [PASS] Correctly rejected NaN probability.")

    # 2. Decoupling of Decision Threshold from Probability
    print("\n[2/5] Auditing Independence of Continuous Probability from Decision Threshold...")
    dummy_model = type("DummyModel", (), {
        "predict_proba": lambda self, X: np.array([[0.13, 0.87]])
    })()

    # Evaluation at standard 0.50 threshold
    res_050 = threat_probability_engine.extract_threat_probability(
        model=dummy_model, X=np.zeros((1, 20)), model_name="Random Forest", threshold=0.50
    )[0]
    assert res_050.threatProbability == 0.87
    assert res_050.threatClass == ThreatClassEnum.THREAT

    # Evaluation at conservative 0.90 threshold
    res_090 = threat_probability_engine.extract_threat_probability(
        model=dummy_model, X=np.zeros((1, 20)), model_name="Random Forest", threshold=0.90
    )[0]
    assert res_090.threatProbability == 0.87  # Probability unchanged
    assert res_090.threatClass == ThreatClassEnum.NORMAL  # Class flipped because 0.87 < 0.90

    print(f"    At Threshold 0.50: Prob={res_050.threatProbability}, Class={res_050.threatClass.value}")
    print(f"    At Threshold 0.90: Prob={res_090.threatProbability}, Class={res_090.threatClass.value}")
    print("    [PASS] Verified that threshold changes decision class while preserving true probability.")

    # 3. Standard Prediction Output Format
    print("\n[3/5] Auditing Standard Display String Formatting...")
    display_str = res_050.to_display_string()
    print("    " + display_str.replace("\n", "\n    "))
    assert "Threat Probability: 0.87 (87.0%)" in display_str
    assert "Threat Class: THREAT" in display_str
    assert "Model: Random Forest" in display_str
    print("    [PASS] Standard formatting verified.")

    # 4. Multi-Model Probability Extraction on Real Test Dataset
    print("\n[4/5] Auditing Multi-Model Probability Extraction on Test Partition...")
    X_train, y_train, X_test, y_test, features = dataset_loader.load_train_test()

    rf = AttackRandomForestClassifier(random_seed=42)
    rf.train(X_train, y_train, feature_names=features)

    lr = AttackLogisticRegressionClassifier(random_seed=42)
    lr.train(X_train, y_train, feature_names=features)

    xgb = AttackXGBoostClassifier(random_seed=42)
    xgb.train(X_train, y_train, feature_names=features)

    test_models = {
        "Logistic Regression": lr,
        "Random Forest": rf,
        "XGBoost": xgb
    }

    comp_results = threat_probability_engine.compare_models_on_test_set(test_models, X_test[:3], y_test[:3])
    assert len(comp_results) == 9  # 3 models * 3 test samples

    for row in comp_results[:3]:
        print(f"    Model: {row['model']:<20} | Sample: {row['sampleIndex']} | Actual: {row['actualLabel']:<9} | Prob: {row['threatProbabilityFormatted']:<6} | Pred: {row['predictedClass']}")
        assert 0.0 <= row["threatProbability"] <= 1.0
    print("    [PASS] Test set evaluated across multiple baseline models cleanly.")

    # 5. Disk Persistence Verification
    print("\n[5/5] Auditing Artifact Persistence to Disk...")
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "predictions" / "threat_probabilities.json"
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        stored_records = json.load(f)
    assert len(stored_records) > 0
    print(f"    Persisted Predictions Count: {len(stored_records)}")
    print("    [PASS] Predictions successfully persisted.")

    print("\n" + "=" * 80)
    print("       ALL DAY 107 THREAT PROBABILITY TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day107_suite()