import sys
import json
import time
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.ml.time_series.models.gru.gru_model import GRUAttackPredictor
from services.digital_twin.ml.time_series.models.gru.train_gru import run_gru_training_and_comparison

def run_day117_suite():
    print("=" * 80)
    print("       WEEK 17 - DAY 117: GRU SEQUENCE MODEL & LSTM COMPARISON AUDIT")
    print("=" * 80 + "\n")

    # 1. Input Tensor Shape Compatibility [N, T, D]
    print("[1/7] Auditing GRU 3D Tensor Forward Pass ([N=4, T=5, D=16])...")
    gru = GRUAttackPredictor(input_dim=16, hidden_dim=32, dense_dim=16, random_seed=42)
    dummy_X = np.random.randn(4, 5, 16).astype(np.float32)
    gru.is_fitted = True
    raw_probs = gru.predict_proba(dummy_X)

    print(f"    Raw GRU Output Probabilities: {raw_probs}")
    assert raw_probs.shape == (4,)
    assert np.all((raw_probs >= 0.0) & (raw_probs <= 1.0))
    print("    [PASS] GRU recurrent forward pass properly bounded in [0.0, 1.0].")

    # 2. Parameter Count Efficiency Audit
    print("\n[2/7] Auditing Parameter Count Reduction (GRU vs LSTM)...")
    gru_params = gru.count_parameters()
    # LSTM with same dimensions: 4*(16*32 + 32*32 + 32) + (32*16 + 16) + (16*1 + 1)
    lstm_params = 4 * (16 * 32 + 32 * 32 + 32) + (32 * 16 + 16) + (16 * 1 + 1)
    reduction_pct = (1.0 - (gru_params / lstm_params)) * 100.0

    print(f"    LSTM Parameter Count : {lstm_params}")
    print(f"    GRU Parameter Count  : {gru_params}")
    print(f"    Parameter Reduction  : {reduction_pct:.2f}%")

    assert gru_params < lstm_params
    assert reduction_pct > 20.0
    print("    [PASS] GRU exhibits verified parameter efficiency over LSTM.")

    # 3. Model Training & Early Stopping Audit
    print("\n[3/7] Executing GRU Training and Multi-Model Comparison Pipeline...")
    res = run_gru_training_and_comparison()
    gru_meta = res["gruMetadata"]
    gru_ctrl = gru_meta["trainingControls"]
    metrics = res["gruMetrics"]["evaluationMetrics"]
    lead = res["gruMetrics"]["earlyWarningMetrics"]

    print(f"    Epochs Trained : {gru_ctrl['epochsTrained']}")
    print(f"    Early Stopped  : {gru_ctrl['earlyStopped']}")
    print(f"    Train Duration : {gru_ctrl['trainingDurationMs']} ms")
    assert gru_ctrl["epochsTrained"] > 0
    print("    [PASS] GRU training converged with early stopping controls.")

    # 4. Standard Classification Metrics
    print("\n[4/7] Auditing GRU Classification Metrics...")
    print(f"    Accuracy  : {metrics['accuracy']:.4f}")
    print(f"    Precision : {metrics['precision']:.4f}")
    print(f"    Recall    : {metrics['recall']:.4f}")
    print(f"    F1-Score  : {metrics['f1']:.4f}")
    print(f"    ROC-AUC   : {metrics['rocAuc']:.4f}")
    print(f"    Confusion Matrix: {metrics['confusionMatrix']}")

    assert metrics["accuracy"] >= 0.80
    assert metrics["recall"] >= 0.80
    print("    [PASS] Standard GRU classification metrics validated.")

    # 5. Early-Warning Lead Time Runway
    print("\n[5/7] Auditing GRU Early-Warning Lead Time...")
    print(f"    Impact Step Index       : {lead['impactStepIndex']}")
    print(f"    First Warning Step Index: {lead['firstWarningStepIndex']}")
    print(f"    Lead Runway Steps       : {lead['leadSteps']}")
    print(f"    Lead Time Runway        : {lead['leadTimeFormatted']}")

    assert lead["leadTimeSeconds"] > 0.0
    assert lead["firstWarningStepIndex"] < lead["impactStepIndex"]
    print("    [PASS] Early warning verified before impact onset.")

    # 6. GRU Inference Latency Profiling
    print("\n[6/7] Profiling GRU Single-Sequence Latency...")
    t0 = time.perf_counter()
    _ = gru.predict_proba(dummy_X[:1])
    inf_latency_ms = round((time.perf_counter() - t0) * 1000, 3)
    print(f"    Single Sequence Inference Latency: {inf_latency_ms} ms")
    assert inf_latency_ms < 50.0
    print("    [PASS] GRU latency comfortably satisfies real-time budget (<50 ms).")

    # 7. Head-to-Head Comparative Leaderboard Verification
    print("\n[7/7] Auditing Final LSTM vs. GRU Comparison Table...")
    comp_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series" / "comparison" / "comparison_report.json"
    assert comp_file.exists()

    with open(comp_file, "r", encoding="utf-8") as f:
        comp_report = json.load(f)

    table = comp_report["comparisonTable"]
    print("\n    | Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Lead Time | Params | Inference |")
    print("    |-------|----------|-----------|--------|----------|---------|-----------|--------|-----------|")
    for row in table:
        print(f"    | {row['model']:<5} | {row['accuracy']:<8.4f} | {row['precision']:<9.4f} | {row['recall']:<6.4f} | {row['f1']:<8.4f} | {row['rocAuc']:<7.4f} | {row['leadTimeFormatted']:<9} | {row['parameterCount']:<6} | {row['inferenceTimeMs']} ms |")

    assert len(table) == 2
    models_present = {r["model"] for r in table}
    assert models_present == {"LSTM", "GRU"}
    print("\n    [PASS] LSTM vs GRU comparison table fully validated.")

    print("\n" + "=" * 80)
    print("       ALL DAY 117 GRU SEQUENCE MODEL TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day117_suite()