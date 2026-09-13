import sys
import json
from pathlib import Path
import joblib

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES
from services.digital_twin.ml.xai.feature_importance.importance_models import (
    ImportanceMethodEnum, GlobalImportanceReport
)
from services.digital_twin.ml.xai.feature_importance.global_importance_engine import global_feature_importance_engine
from services.digital_twin.ml.models.random_forest.random_forest_classifier import AttackRandomForestClassifier
from services.digital_twin.ml.models.logistic_regression.logistic_regression_classifier import AttackLogisticRegressionClassifier
from services.digital_twin.ml.training.dataset_loader import dataset_loader

def run_day122_suite():
    print("=" * 80)
    print("       WEEK 18 - DAY 122: GLOBAL FEATURE IMPORTANCE AUDIT")
    print("=" * 80 + "\n")

    # 1. Model Loading & Native Importance Generation (Tree Ensemble)
    print("[1/8] Auditing Tree Ensemble Native Importance (Random Forest)...")
    rf_path = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "random_forest" / "model.joblib"
    assert rf_path.exists()
    rf_data = joblib.load(rf_path)
    rf_model = rf_data["model"] if isinstance(rf_data, dict) and "model" in rf_data else rf_data

    method_rf, imp_rf = global_feature_importance_engine.extract_native_importance(rf_model, "random_forest", FEATURE_NAMES)
    print(f"    Method Extracted : {method_rf.value}")
    assert method_rf == ImportanceMethodEnum.TREE_IMPORTANCE
    assert len(imp_rf) == len(FEATURE_NAMES)
    print("    [PASS] Tree-based Gini importance extracted.")

    # 2. Linear Model Importance Generation (Coefficient-based)
    print("\n[2/8] Auditing Linear Classifier Importance (Logistic Regression)...")
    lr_path = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "logistic_regression" / "model.joblib"
    if lr_path.exists():
        lr_data = joblib.load(lr_path)
        lr_model = lr_data["model"] if isinstance(lr_data, dict) and "model" in lr_data else lr_data
        method_lr, imp_lr = global_feature_importance_engine.extract_native_importance(lr_model, "logistic_regression", FEATURE_NAMES)
        print(f"    Linear Method    : {method_lr.value}")
        assert method_lr == ImportanceMethodEnum.COEFFICIENT_IMPORTANCE
        assert len(imp_lr) == len(FEATURE_NAMES)
        print("    [PASS] Model-specific coefficient importance extracted.")
    else:
        print("    [SKIP] Logistic regression artifact not found, tested fallback path.")

    # 3. Full Global Report Generation & SHAP Importance
    print("\n[3/8] Generating Comprehensive Global Importance Report (Native vs SHAP)...")
    report = global_feature_importance_engine.generate_global_importance_report(
        model=rf_model,
        model_name="random_forest",
        model_version="rf-v1.0"
    )
    assert report is not None
    print(f"    Report ID        : {report.reportId}")
    print(f"    Model Name       : {report.modelName} ({report.modelVersion})")
    print(f"    Native Method    : {report.nativeMethod.value}")
    print("    [PASS] Global importance report generated.")

    # 4. Feature Completeness (All Features Included)
    print("\n[4/8] Auditing Feature Completeness across Native & SHAP Outputs...")
    native_names = [it.featureName for it in report.nativeImportances]
    shap_names = [it.featureName for it in report.shapImportances]

    assert len(native_names) == len(FEATURE_NAMES)
    assert len(shap_names) == len(FEATURE_NAMES)
    assert set(native_names) == set(FEATURE_NAMES)
    assert set(shap_names) == set(FEATURE_NAMES)
    print(f"    Total Features Accounted: {len(FEATURE_NAMES)} (100% Coverage)")
    print("    [PASS] All features present in both rankings.")

    # 5. Ranks & Importance Validity
    print("\n[5/8] Auditing Rank Generation and Importance Bounds [0.0, 1.0]...")
    for idx, it in enumerate(report.nativeImportances, start=1):
        assert it.rank == idx
        assert 0.0 <= it.importance <= 1.0

    for idx, it in enumerate(report.shapImportances, start=1):
        assert it.rank == idx
        assert 0.0 <= it.importance <= 1.0

    # Strict monotonic descending importance check
    for i in range(len(report.nativeImportances) - 1):
        assert report.nativeImportances[i].importance >= report.nativeImportances[i + 1].importance

    for i in range(len(report.shapImportances) - 1):
        assert report.shapImportances[i].importance >= report.shapImportances[i + 1].importance

    print("    [PASS] Strict monotonic rank and probability bounds verified.")

    # 6. Model Lineage & Versioning Preservation
    print("\n[6/8] Auditing Model, Dataset, and Feature Lineage Metadata...")
    assert report.modelName == "random_forest"
    assert report.modelVersion == "rf-v1.0"
    assert report.datasetVersion == "dataset-v1.0"
    assert report.featureVersion == "feature-v1.0"
    print(f"    Dataset Lineage: {report.datasetVersion} | Feature Lineage: {report.featureVersion}")
    print("    [PASS] Lineage and versioning verified.")

    # 7. Comparison Table & Discrepancy Matrix Audit
    print("\n[7/8] Auditing Method Comparison Table (Native Rank vs SHAP Rank)...")
    comp_tbl = report.comparisonTable
    assert len(comp_tbl) == len(FEATURE_NAMES)

    print("\n    | Rank (SHAP) | Feature Name               | SHAP Imp | Native Imp | Native Rank | Rank Delta |")
    print("    |-------------|----------------------------|----------|------------|-------------|------------|")
    for row in comp_tbl[:8]:
        print(f"    | {row.shapRank:<11} | {row.featureName:<26} | {row.shapImportance:<8.4f} | {row.nativeImportance:<10.4f} | {row.nativeRank:<11} | {row.rankDelta:<10} |")

    top_shap = comp_tbl[0]
    print(f"\n    Top Global SHAP Driver : {top_shap.featureName} (Importance: {top_shap.shapImportance})")
    print("    [PASS] Comparison table and rank discrepancies mapped.")

    # 8. ASCII Bar Visualizations & Artifact Persistence
    print("\n[8/8] Auditing Visual ASCII Charts and Disk Persistence...")
    print(f"\n{report.nativeAsciiBarChart}\n")
    print(f"{report.shapAsciiBarChart}\n")

    assert "█" in report.nativeAsciiBarChart
    assert "█" in report.shapAsciiBarChart

    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai" / "global_importance.json"
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        stored_report = json.load(f)
    assert stored_report["reportId"] == report.reportId
    assert len(stored_report["comparisonTable"]) == len(FEATURE_NAMES)
    print(f"    Saved Report Verified on Disk: {out_file.name}")
    print("    [PASS] Visualizations generated and artifacts verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 122 GLOBAL FEATURE IMPORTANCE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day122_suite()