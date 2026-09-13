import json
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[5]
TS_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series"

from services.digital_twin.ml.time_series.features.temporal_feature_engine import temporal_feature_engine
from services.digital_twin.ml.time_series.windows.window_models import SlidingWindowConfig, TemporalSequence
from services.digital_twin.ml.time_series.windows.sliding_window_generator import SlidingWindowGenerator

class SequenceDatasetBuilder:
    """Builds and serializes sequential training datasets for LSTM, GRU, and temporal models."""

    def __init__(self, artifacts_dir: Path = TS_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def generate_scenario_stream(
        self,
        scenario_type: str = "DOS_ATTACK_ESCALATION",
        total_steps: int = 40
    ) -> List[Dict[str, Any]]:
        """Synthesizes chronological multi-stage scenario telemetry for temporal training."""
        stream = []
        rng = np.random.RandomState(42)

        for t in range(total_steps):
            # Lifecycle stages:
            # 0-14: NORMAL
            # 15-22: EARLY_INDICATORS
            # 23-29: ESCALATION
            # 30-36: IMPACT
            # 37-39: RECOVERY
            if t < 15:
                stage = "NORMAL"
                label = "NORMAL"
                pkt_rate = float(rng.normal(20.0, 2.0))
                bytes_rate = float(rng.normal(10000.0, 1000.0))
            elif t < 23:
                stage = "EARLY_INDICATORS"
                label = "NORMAL"  # Observation itself still below threshold, but trajectory escalating
                ramp = (t - 14) * 8.0
                pkt_rate = 20.0 + ramp + float(rng.normal(0, 1.5))
                bytes_rate = 10000.0 + (ramp * 600.0)
            elif t < 30:
                stage = "ESCALATION"
                label = "ANOMALOUS"
                ramp = (t - 22) * 20.0
                pkt_rate = 84.0 + ramp + float(rng.normal(0, 3.0))
                bytes_rate = 55000.0 + (ramp * 1500.0)
            elif t < 37:
                stage = "IMPACT"
                label = "ANOMALOUS"
                pkt_rate = float(rng.normal(300.0, 15.0))
                bytes_rate = float(rng.normal(350000.0, 20000.0))
            else:
                stage = "RECOVERY"
                label = "NORMAL"
                pkt_rate = float(rng.normal(25.0, 3.0))
                bytes_rate = float(rng.normal(12000.0, 1500.0))

            stream.append({
                "timeStep": t,
                "packet_rate": round(max(0.0, pkt_rate), 2),
                "bytes_per_second": round(max(0.0, bytes_rate), 2),
                "bytes": round(max(0.0, bytes_rate * 5.0), 2),
                "connection_frequency": round(max(0.0, pkt_rate / 10.0), 2),
                "flow_duration": 5.0,
                "failed_connections": 5.0 if stage == "IMPACT" else 0.0,
                "dns_frequency": 0.5,
                "destination_diversity": 0.2,
                "label": label,
                "stage": stage,
                "scenario": scenario_type
            })

        return stream

    def build_dataset(
        self,
        config: SlidingWindowConfig = SlidingWindowConfig(windowSize=5, stepSize=1, predictionHorizon=2)
    ) -> Dict[str, Any]:
        stream = self.generate_scenario_stream("DOS_ATTACK_ESCALATION", total_steps=40)
        observations = temporal_feature_engine.process_telemetry_stream(stream)

        generator = SlidingWindowGenerator(config=config)
        train_seqs, test_seqs = generator.chronological_train_test_split(observations, train_ratio=0.70)

        X_train, y_train, cat_train = generator.to_tensors(train_seqs)
        X_test, y_test, cat_test = generator.to_tensors(test_seqs)

        metadata = {
            "datasetVersion": "seq-v1.0",
            "windowSize": config.windowSize,
            "stepSize": config.stepSize,
            "predictionHorizon": config.predictionHorizon,
            "featureDim": config.featureDim,
            "trainSequenceCount": int(X_train.shape[0]),
            "testSequenceCount": int(X_test.shape[0]),
            "trainTensorShape": [int(s) for s in X_train.shape],
            "testTensorShape": [int(s) for s in X_test.shape],
            "positiveTrainRate": round(float(np.mean(y_train)), 4) if len(y_train) > 0 else 0.0,
            "positiveTestRate": round(float(np.mean(y_test)), 4) if len(y_test) > 0 else 0.0
        }

        with open(self.artifacts_dir / "sequence_dataset_metadata.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return {
            "X_train": X_train,
            "y_train": y_train,
            "X_test": X_test,
            "y_test": y_test,
            "metadata": metadata
        }

sequence_dataset_builder = SequenceDatasetBuilder()