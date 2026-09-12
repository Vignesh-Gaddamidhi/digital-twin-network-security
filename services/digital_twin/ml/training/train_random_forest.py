import json
from pathlib import Path
from typing import Dict, Any

ROOT_DIR = Path(__file__).resolve().parents[4]
ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "random_forest"

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.models.random_forest.random_forest_classifier import AttackRandomForestClassifier

def run_random_forest_training() -> Dict[str, Any]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    X_train, y_train, X_test, y_test, feature_names = dataset_loader.load_train_test()

    clf = AttackRandomForestClassifier(random_seed=42)
    meta = clf.train(X_train, y_train, feature_names=feature_names)
    metrics = clf.evaluate(X_test, y_test)
    feature_importances = clf.get_feature_importances(feature_names)
    oob_score = clf.get_oob_score()

    model_path = ARTIFACTS_DIR / "model.joblib"
    clf.save(model_path)

    metadata_dict = {
        "experimentId": meta.experimentId,
        "modelName": "random_forest",
        "datasetVersion": meta.datasetVersion,
        "featureVersion": meta.featureVersion,
        "trainingSamples": int(X_train.shape[0]),
        "testingSamples": int(X_test.shape[0]),
        "featureCount": len(feature_names),
        "hyperparameters": clf.hyperparameters,
        "randomSeed": clf.random_seed,
        "oobScore": oob_score
    }
    with open(ARTIFACTS_DIR / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata_dict, f, indent=2)

    # Format ranked feature table
    ranked_features = [
        {"rank": idx + 1, "feature": k, "importance": v}
        for idx, (k, v) in enumerate(feature_importances.items())
    ]

    metrics_dict = {
        "standardEvaluation": metrics.model_dump(),
        "oobScore": oob_score,
        "rankedFeatureTable": ranked_features,
        "featureImportances": feature_importances
    }
    with open(ARTIFACTS_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_dict, f, indent=2)

    return {
        "metadata": metadata_dict,
        "metrics": metrics_dict,
        "artifactsPath": str(ARTIFACTS_DIR)
    }

if __name__ == "__main__":
    result = run_random_forest_training()
    print("Random Forest Training Complete.")
    print(json.dumps(result["metrics"]["standardEvaluation"], indent=2))