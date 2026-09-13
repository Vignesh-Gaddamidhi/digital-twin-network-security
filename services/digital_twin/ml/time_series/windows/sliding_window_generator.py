from typing import Dict, Any, List, Tuple, Optional
import numpy as np

from services.digital_twin.ml.time_series.features.time_series_models import TimeSeriesObservation
from services.digital_twin.ml.time_series.windows.window_models import SlidingWindowConfig, TemporalSequence

class SlidingWindowGenerator:
    """Generates 3D sequential tensors and early-warning horizon targets from time-series streams."""

    SEVERITY_HIERARCHY = [
        "NORMAL", "PORT_SCAN", "BEACONING", "DNS_ANOMALY",
        "BRUTE_FORCE_LIKE", "DOS_LIKE", "LATERAL_MOVEMENT_LIKE", "EXFILTRATION_LIKE"
    ]

    def __init__(self, config: SlidingWindowConfig = SlidingWindowConfig()):
        self.config = config

    def create_sequences(
        self,
        observations: List[TimeSeriesObservation],
        index_offset: int = 0
    ) -> List[TemporalSequence]:
        total_obs = len(observations)
        required_len = self.config.windowSize + self.config.predictionHorizon

        if total_obs < required_len:
            return []

        sequences: List[TemporalSequence] = []
        max_start = total_obs - required_len + 1

        for rel_start in range(0, max_start, self.config.stepSize):
            rel_window_end = rel_start + self.config.windowSize
            rel_horizon_end = rel_window_end + self.config.predictionHorizon

            window_slice = observations[rel_start:rel_window_end]
            horizon_slice = observations[rel_window_end:rel_horizon_end]

            # Determine absolute indices preserving global chronological alignment
            abs_start = window_slice[0].timeStepIndex if hasattr(window_slice[0], "timeStepIndex") and window_slice[0].timeStepIndex != 0 else (rel_start + index_offset)
            abs_window_end = abs_start + self.config.windowSize
            abs_horizon_end = abs_window_end + self.config.predictionHorizon

            # Construct 2D feature matrix [T, D]
            feat_matrix = [obs.to_flat_feature_vector() for obs in window_slice]
            timestamps = [obs.timestamp for obs in window_slice]

            # Determine future ground truth target over horizon H
            future_labels = [obs.label for obs in horizon_slice]
            has_threat = any(lbl not in ("NORMAL", "0", 0) for lbl in future_labels)
            future_binary = 1 if has_threat else 0

            # Rank most severe category in horizon
            top_category = "NORMAL"
            highest_sev = 0
            for lbl in future_labels:
                lbl_up = str(lbl).upper()
                if lbl_up in self.SEVERITY_HIERARCHY:
                    sev = self.SEVERITY_HIERARCHY.index(lbl_up)
                    if sev > highest_sev:
                        highest_sev = sev
                        top_category = lbl_up
                elif lbl_up not in ("NORMAL", "0"):
                    top_category = lbl_up

            tail_obs = window_slice[-1]
            seq_stage = tail_obs.stage

            seq = TemporalSequence(
                startIndex=abs_start,
                endIndex=abs_window_end - 1,
                horizonStartIndex=abs_window_end,
                horizonEndIndex=abs_horizon_end - 1,
                timeTimestamps=timestamps,
                featureMatrix=feat_matrix,
                futureThreatBinary=future_binary,
                futureThreatCategory=top_category,
                futureThreatProbabilityTarget=1.0 if future_binary == 1 else 0.0,
                sequenceStage=seq_stage,
                metadata={
                    "windowSize": self.config.windowSize,
                    "predictionHorizon": self.config.predictionHorizon,
                    "stepSize": self.config.stepSize
                }
            )
            sequences.append(seq)

        return sequences

    def to_tensors(
        self,
        sequences: List[TemporalSequence]
    ) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        if not sequences:
            empty_x = np.empty((0, self.config.windowSize, self.config.featureDim), dtype=np.float32)
            empty_y = np.empty((0,), dtype=np.int64)
            return empty_x, empty_y, []

        X = np.array([seq.featureMatrix for seq in sequences], dtype=np.float32)
        y = np.array([seq.futureThreatBinary for seq in sequences], dtype=np.int64)
        categories = [seq.futureThreatCategory for seq in sequences]

        return X, y, categories

    def chronological_train_test_split(
        self,
        observations: List[TimeSeriesObservation],
        train_ratio: float = 0.75
    ) -> Tuple[List[TemporalSequence], List[TemporalSequence]]:
        total_obs = len(observations)
        split_point = int(total_obs * train_ratio)

        # Buffer gap equal to prediction horizon H prevents target leakage
        buffer_gap = self.config.predictionHorizon
        test_start_idx = split_point + buffer_gap

        train_obs = observations[:split_point]
        test_obs = observations[test_start_idx:]

        train_seqs = self.create_sequences(train_obs, index_offset=0)
        test_seqs = self.create_sequences(test_obs, index_offset=test_start_idx)

        return train_seqs, test_seqs

sliding_window_generator = SlidingWindowGenerator()