import json
from pathlib import Path
from typing import Dict, Any

ROOT_DIR = Path(__file__).resolve().parents[4]
ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "svm"

from services.digital_twin.ml.training.dataset_loader import dataset_loader
from services.digital_twin.ml.models.svm.svm_classifier import AttackSVMClassifier

def run_svm_training() -> Dict[str, Any]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    X_train, y_train, X_test, y_test, feature_names = dataset_loader.load_train_test()

    clf = AttackSVMClassifier(random_seed=42)
    meta = clf.train(X_train, y_train, feature_names=feature_names)
    metrics = clf.evaluate(X_test, y_test)
    sv_stats = clf.get_support_vector_stats()

    model_path = ARTIFACTS_DIR / "model.joblib"
    clf.save(model_path)

    metadata_dict = {
        "experimentId": meta.experimentId,
        "modelName": "svm",
        "datasetVersion": meta.datasetVersion,
        "featureVersion": meta.featureVersion,
        "trainingSamples": int(X_train.shape[0]),
        "testingSamples": int(X_test.shape[0]),
        "featureCount": len(feature_names),
        "hyperparameters": clf.hyperparameters,
        "randomSeed": clf.random_seed,
        "supportVectorStats": sv_stats
    }
    with open(ARTIFACTS_DIR / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata_dict, f, indent=2)

    metrics_dict = {
        "standardEvaluation": metrics.model_dump(),
        "supportVectorStats": sv_stats
    }
    with open(ARTIFACTS_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_dict, f, indent=2)

    return {
        "metadata": metadata_dict,
        "metrics": metrics_dict,
        "artifactsPath": str(ARTIFACTS_DIR)
    }

if __name__ == "__main__":
    result = run_svm_training()
    print("SVM Training & Evaluation Complete.")
    print(json.dumps(result["metrics"]["standardEvaluation"], indent=2))