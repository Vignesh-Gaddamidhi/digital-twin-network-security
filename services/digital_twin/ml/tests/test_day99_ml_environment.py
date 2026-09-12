import sys
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.training.dataset_loader import dataset_loader, FEATURE_NAMES
from services.digital_twin.ml.models.baseline_mock_classifier import BaselineVerificationClassifier

def run_day99_suite():
    print("=" * 80)
    print("       WEEK 15 - DAY 99: ML ENVIRONMENT & BASELINE PIPELINE AUDIT")
    print("=" * 80 + "\n")

    # 1. Dependency stack verification
    print("[1/6] Auditing Core ML Package Availability...")
    import numpy as np
    import pandas as pd
    import sklearn
    import xgboost as xgb
    import joblib
    print(f"    NumPy Version   : {np.__version__}")
    print(f"    Pandas Version  : {pd.__version__}")
    print(f"    Scikit-Learn    : {sklearn.__version__}")
    print(f"    XGBoost Version : {xgb.__version__}")
    print("    [PASS] Dependency stack validated.")

    # 2. Dataset loading and matrix preparation
    print("\n[2/6] Auditing DatasetLoader (X and y Preparation)...")
    X_train, y_train, X_test, y_test, features = dataset_loader.load_train_test()

    print(f"    X_train Shape   : {X_train.shape}")
    print(f"    y_train Shape   : {y_train.shape}")
    print(f"    X_test Shape    : {X_test.shape}")
    print(f"    y_test Shape    : {y_test.shape}")

    assert X_train.ndim == 2
    assert y_train.ndim == 1
    assert X_train.shape[0] == y_train.shape[0]
    assert X_test.shape[0] == y_test.shape[0]
    assert X_train.shape[1] == 20
    assert X_test.shape[1] == 20
    print("    [PASS] Matrix dimensions and row alignments confirmed.")

    # 3. Target label encoding
    print("\n[3/6] Auditing Target Label Validity (y in {0, 1})...")
    unique_train = set(np.unique(y_train))
    unique_test = set(np.unique(y_test))
    print(f"    Unique y_train classes : {unique_train}")
    print(f"    Unique y_test classes  : {unique_test}")

    assert unique_train.issubset({0, 1})
    assert unique_test.issubset({0, 1})
    assert 0 in unique_train and 1 in unique_train
    print("    [PASS] Ground truth targets cleanly encoded as binary integers.")

    # 4. Zero Target Leakage Invariant
    print("\n[4/6] Auditing Zero Target Leakage in Predictor Columns...")
    banned_tokens = ["label", "target", "scenario", "attack", "alert", "threat", "anomaly"]
    for fn in features:
        for b in banned_tokens:
            assert b not in fn.lower(), f"Leakage detected in feature name: '{fn}' contains '{b}'"

    assert len(features) == 20
    assert "packet_rate" in features
    assert "port_443_ratio" in features
    print("    [PASS] Verified 20 pure predictor features with zero target contamination.")

    # 5. Common Model Interface Contract Execution
    print("\n[5/6] Auditing Common Interface (train -> predict -> evaluate)...")
    clf = BaselineVerificationClassifier(random_seed=42)
    meta = clf.train(X_train, y_train, feature_names=features)

    assert clf.is_fitted is True
    assert meta.modelName == "baseline_verification"
    assert meta.trainingRecordsCount == X_train.shape[0]

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)

    assert preds.shape == (X_test.shape[0],)
    assert probs.shape == (X_test.shape[0], 2)
    assert np.allclose(probs.sum(axis=1), 1.0)

    metrics = clf.evaluate(X_test, y_test)
    print(f"    Evaluation Accuracy : {metrics.accuracy}")
    print(f"    Evaluation F1-Score : {metrics.f1Score}")
    print(f"    Confusion Matrix    : {metrics.confusionMatrix}")

    assert 0.0 <= metrics.accuracy <= 1.0
    assert 0.0 <= metrics.f1Score <= 1.0
    assert len(metrics.confusionMatrix) == 2
    print("    [PASS] Common model lifecycle executed cleanly with standard metric calculation.")

    # 6. Artifact Serialization & Deserialization
    print("\n[6/6] Auditing Model Persistence (save -> load)...")
    saved_path = clf.save()
    assert saved_path.exists()

    loaded_clf = BaselineVerificationClassifier()
    loaded_clf.load(saved_path)
    assert loaded_clf.is_fitted is True
    assert loaded_clf.metadata.modelName == "baseline_verification"

    loaded_preds = loaded_clf.predict(X_test)
    assert np.array_equal(preds, loaded_preds)
    print(f"    [PASS] Model artifact saved to {saved_path.name} and reloaded with identical predictions.")

    print("\n" + "=" * 80)
    print("       ALL DAY 99 ML ENVIRONMENT TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_day99_suite()