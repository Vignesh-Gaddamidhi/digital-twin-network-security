import json
import time
from pathlib import Path
from typing import Dict, Any

ROOT_DIR = Path(__file__).resolve().parents[5]
LSTM_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series" / "lstm"

from services.digital_twin.ml.time_series.sequences.sequence_dataset_builder import sequence_dataset_builder
from services.digital_twin.ml.time_series.features.temporal_feature_engine import temporal_feature_engine
from services.digital_twin.ml.time_series.windows.sliding_window_generator import SlidingWindowGenerator
from services.digital_twin.ml.time_series.windows.window_models import SlidingWindowConfig
from services.digital_twin.ml.time_series.models.lstm_model import LSTMAttackPredictor
from services.digital_twin.ml.time_series.features.feature_registry import temporal_feature_registry

def run_lstm_training() -> Dict[str, Any]:
    LSTM_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Build Multi-Stage Training Sequence
    cfg = SlidingWindowConfig(windowSize=5, stepSize=1, predictionHorizon=3, featureDim=16)
    dataset = sequence_dataset_builder.build_dataset(config=cfg)

    X_train, y_train = dataset["X_train"], dataset["y_train"]
    X_test, y_test = dataset["X_test"], dataset["y_test"]

    # 2. Train LSTM Model
    t0 = time.perf_counter()
    model = LSTMAttackPredictor(
        input_dim=cfg.featureDim,
        hidden_dim=32,
        dense_dim=16,
        dropout=0.20,
        learning_rate=0.05,
        random_seed=42
    )

    train_summary = model.fit(
        X_train, y_train,
        X_val=X_test, y_val=y_test,
        epochs=50, batch_size=8, patience=10, min_epochs=15
    )
    train_duration_ms = round((time.perf_counter() - t0) * 1000, 2)

    # 3. Evaluate Metrics
    metrics = model.evaluate(X_test, y_test)

    # 4. Measure Early-Warning Lead Time on Full Scenario Stream
    stream = sequence_dataset_builder.generate_scenario_stream("DOS_ATTACK_ESCALATION", total_steps=40)
    obs = temporal_feature_engine.process_telemetry_stream(stream)
    gen = SlidingWindowGenerator(config=cfg)
    all_seqs = gen.create_sequences(obs)

    # Impact begins at step index 30 in the synthesized scenario
    lead_time_audit = model.measure_early_warning_lead_time(
        sequences=all_seqs,
        impact_timestamp_idx=30,
        interval_seconds=5.0
    )

    # 5. Persist Model Artifacts
    model.save(LSTM_DIR)

    metadata = {
        "modelName": "lstm",
        "modelVersion": "lstm-v1.0",
        "datasetVersion": "seq-v1.0",
        "featureVersion": "ts-feat-v1.0",
        "trainingControls": {
            "sequenceLength": cfg.windowSize,
            "featureCount": cfg.featureDim,
            "predictionHorizon": cfg.predictionHorizon,
            "hiddenUnits": 32,
            "dropout": 0.20,
            "learningRate": 0.01,
            "optimizer": "Adam",
            "loss": "binary_crossentropy",
            "epochsTrained": train_summary["epochsTrained"],
            "earlyStopped": train_summary["earlyStopped"],
            "trainingDurationMs": train_duration_ms,
            "randomSeed": 42
        }
    }
    with open(LSTM_DIR / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    metrics_report = {
        "evaluationMetrics": metrics,
        "earlyWarningMetrics": lead_time_audit,
        "trainingSummary": train_summary
    }
    with open(LSTM_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_report, f, indent=2)

    with open(LSTM_DIR / "feature_schema.json", "w", encoding="utf-8") as f:
        json.dump({
            "featureDim": cfg.featureDim,
            "sequenceLength": cfg.windowSize,
            "registeredFeatures": temporal_feature_registry.get_feature_names()
        }, f, indent=2)

    return {
        "metadata": metadata,
        "metrics": metrics_report,
        "leadTime": lead_time_audit
    }

if __name__ == "__main__":
    res = run_lstm_training()
    print("LSTM Training & Evaluation Complete.")
    print(json.dumps(res, indent=2))