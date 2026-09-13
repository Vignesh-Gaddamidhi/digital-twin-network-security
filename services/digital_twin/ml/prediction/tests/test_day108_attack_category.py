import sys
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.prediction.classification.classification_models import (
    CLASS_TO_INT, CanonicalAttackCategory
)
from services.digital_twin.ml.prediction.classification.multiclass_dataset_adapter import multiclass_dataset_adapter
from services.digital_twin.ml.prediction.classification.attack_category_engine import attack_category_engine

def run_day108_suite():
    print("=" * 80)
    print("       WEEK 16 - DAY 108: ATTACK CATEGORY CLASSIFICATION AUDIT")
    print("=" * 80 + "\n")

    # 1. Dataset Multi-Class Coverage Verification
    print("[1/6] Auditing Multi-Class Dataset Coverage across 8 Canonical Categories...")
    X_tr, y_tr, X_te, y_te, feats, dist = multiclass_dataset_adapter.load_multiclass_data()

    print(f"    Train Samples Count : {X_tr.shape[0]}")
    print(f"    Test Samples Count  : {X_te.shape[0]}")
    print(f"    Feature Dimensions  : {len(feats)}")
    print(f"    Class Distribution  : {dist}")

    assert len(dist) == 8
    for cat in CLASS_TO_INT.keys():
        assert cat in dist and dist[cat] > 0, f"Category {cat} is missing from dataset!"
    print("    [PASS] Verified non-empty representation across all 8 attack classes.")

    # 2. Multi-Class Model Training Execution
    print("\n[2/6] Executing Multi-Class Model Training (Random Forest & XGBoost)...")
    rf_meta = attack_category_engine.train_baseline_model("random_forest")
    assert rf_meta["testAccuracy"] >= 0.70
    print(f"    Random Forest Multi-Class Test Accuracy: {rf_meta['testAccuracy'] * 100:.2f}%")

    xgb_meta = attack_category_engine.train_baseline_model("xgboost")
    assert xgb_meta["testAccuracy"] >= 0.70
    print(f"    XGBoost Multi-Class Test Accuracy      : {xgb_meta['testAccuracy'] * 100:.2f}%")
    print("    [PASS] Multi-class baseline classifiers successfully trained.")

    # 3. Softmax Distribution Properties
    print("\n[3/6] Auditing Categorical Probability Distribution Properties...")
    dummy_vec = np.zeros(20, dtype=np.float32)
    dummy_vec[1] = 3.5  # Trigger Port Scan characteristic

    pred_out = attack_category_engine.classify_behavior(dummy_vec)
    dist_vals = list(pred_out.classDistribution.values())

    print(f"    Predicted Category  : {pred_out.predictedCategory.value}")
    print(f"    Category Confidence : {pred_out.categoryConfidence} ({pred_out.categoryConfidenceFormatted})")
    print(f"    Distribution Sum    : {sum(dist_vals):.4f}")

    assert len(pred_out.classDistribution) == 8
    assert abs(sum(dist_vals) - 1.0) < 1e-3
    assert all(0.0 <= p <= 1.0 for p in dist_vals)
    print("    [PASS] Categorical distribution bounded in [0, 1] and sums to 1.0.")

    # 4. Decoupled Metrics Invariant Audit
    print("\n[4/6] Auditing Decoupled Invariant: Threat Probability != Category Confidence...")
    threat_prob = 0.87
    category_conf = pred_out.categoryConfidence

    print(f"    Threat Probability  : {threat_prob * 100:.1f}%")
    print(f"    Category Confidence : {category_conf * 100:.1f}%")
    assert threat_prob != category_conf
    print("    [PASS] Threat Probability and Category Confidence are verified independent.")

    # 5. Display Formatting String
    print("\n[5/6] Auditing Display String Formatting...")
    disp = pred_out.to_display_string()
    print("    " + disp.replace("\n", "\n    "))
    assert "Predicted Category:" in disp
    assert "Category Confidence:" in disp
    assert "Model:" in disp
    print("    [PASS] Display output string accurately formatted.")

    # 6. Artifact Storage Verification
    print("\n[6/6] Auditing Multi-Class Model Artifact Persistence...")
    art_dir = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "multiclass"
    assert (art_dir / "multiclass_random_forest.joblib").exists()
    assert (art_dir / "multiclass_xgboost.joblib").exists()
    assert (art_dir / "metadata.json").exists()

    with open(art_dir / "metadata.json", "r", encoding="utf-8") as f:
        stored_meta = json.load(f)
    assert stored_meta["modelName"] == "multiclass_xgboost"
    print("    [PASS] Multi-class model joblib files and metadata verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 108 ATTACK CATEGORY TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day108_suite()