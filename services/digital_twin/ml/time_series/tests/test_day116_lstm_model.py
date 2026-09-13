import sys
import time
import json
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.time_series.models.lstm_model import LSTMAttackPredictor
from services.digital_twin.ml.time_series.models.train_lstm import run_lstm_training

def run_day116_suite():
    print("=" * 80)
    print("       WEEK 17 - DAY 116: LSTM SEQUENCE PREDICTION AUDIT")
    print("=" * 80 + "\n")

    # 1. Input Tensor Shape Compatibility [N, T, D]
    print("[1/6] Auditing 3D Tensor Forward Pass ([N=4, T=5, D=16])...")
    model = LSTMAttackPredictor(input_dim=16, hidden_dim=32, dense_dim=16, random_seed=42)
    dummy_X = np.random.randn(4, 5, 16).astype(np.float32)
    model.is_fitted = True  # Enable testing forward pass
    raw_probs = model.predict_proba(dummy_X)

    print(f"    Raw Output Probabilities: {raw_probs}")
    assert raw_probs.shape == (4,)
    assert np.all((raw_probs >= 0.0) & (raw_probs <= 1.0))
    print("    [PASS] 3D recurrent forward pass properly bounded in [0.0, 1.0].")

    # 2. Sequence Model Training & Early Stopping Audit
    print("\n[2/6] Executing Model Training with Early Stopping...")
    res = run_lstm_training()
    meta = res["metadata"]
    train_ctrl = meta["trainingControls"]
    metrics = res["metrics"]["evaluationMetrics"]
    lead = res["leadTime"]

    print(f"    Epochs Trained : {train_ctrl['epochsTrained']}")
    print(f"    Early Stopped  : {train_ctrl['earlyStopped']}")
    print(f"    Train Duration : {train_ctrl['trainingDurationMs']} ms")
    assert train_ctrl["epochsTrained"] > 0
    print("    [PASS] Model training completed with early stopping controls.")

    # 3. Standard Evaluation Metrics
    print("\n[3/6] Auditing Classification Metrics on Test Horizon...")
    print(f"    Accuracy  : {metrics['accuracy']:.4f}")
    print(f"    Precision : {metrics['precision']:.4f}")
    print(f"    Recall    : {metrics['recall']:.4f}")
    print(f"    F1-Score  : {metrics['f1']:.4f}")
    print(f"    ROC-AUC   : {metrics['rocAuc']:.4f}")
    print(f"    Confusion Matrix: {metrics['confusionMatrix']}")

    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert len(metrics["confusionMatrix"]) == 2
    print("    [PASS] Standard classification metrics calculated.")

    # 4. Critical Early-Warning Lead Time Audit
    print("\n[4/6] Auditing Early-Warning Lead Time...")
    print(f"    Impact Step Index       : {lead['impactStepIndex']}")
    print(f"    First Warning Step Index: {lead['firstWarningStepIndex']}")
    print(f"    Lead Runway Steps       : {lead['leadSteps']}")
    print(f"    Lead Time Runway        : {lead['leadTimeFormatted']}")

    assert lead["leadTimeSeconds"] > 0.0
    assert lead["firstWarningStepIndex"] < lead["impactStepIndex"]
    print("    [PASS] Early warning verified before impact threshold arrival.")

    # 5. Model Inference Latency Profiling
    print("\n[5/6] Profiling LSTM Inference Latency...")
    t0 = time.perf_counter()
    p = model.predict_proba(dummy_X[:1])
    inf_latency_ms = round((time.perf_counter() - t0) * 1000, 3)
    print(f"    Single Sequence Inference Latency: {inf_latency_ms} ms")
    assert inf_latency_ms < 50.0  # Real-time budget
    print("    [PASS] Inference latency well within real-time budget.")

    # 6. Artifact & Schema Persistence Audit
    print("\n[6/6] Auditing Artifact Persistence to Disk...")
    art_dir = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series" / "lstm"
    assert (art_dir / "model.joblib").exists()
    assert (art_dir / "metadata.json").exists()
    assert (art_dir / "metrics.json").exists()
    assert (art_dir / "feature_schema.json").exists()

    with open(art_dir / "metadata.json", "r", encoding="utf-8") as f:
        stored_meta = json.load(f)
    assert stored_meta["modelName"] == "lstm"
    assert stored_meta["modelVersion"] == "lstm-v1.0"
    print("    [PASS] All 4 model artifacts and schemas validated on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 116 LSTM ATTACK PREDICTION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day116_suite()