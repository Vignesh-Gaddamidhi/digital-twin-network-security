import json
import math
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class AnomalyScorer:
    """Calculates continuous anomaly scores [0 - 100] using calibrated Z-score deviations."""

    WEIGHTS = {
        "packet_rate": 0.25,
        "byte_rate": 0.20,
        "unique_destinations": 0.25,
        "unique_ports": 0.20,
        "syn_to_ack_ratio": 0.10
    }

    @staticmethod
    def map_z_to_penalty(z: float) -> float:
        """Transforms a Z-score into a continuous penalty score [0.0 - 100.0]."""
        if z <= 2.0:
            return 0.0
        elif z <= 5.0:
            return (z - 2.0) * 15.0  # Scales 0.0 to 45.0
        else:
            return min(100.0, 45.0 + (z - 5.0) * 11.0)

    @classmethod
    def compute_composite_score(cls, feature_vector: Dict[str, float], baseline: Dict[str, Dict[str, float]]) -> Dict[str, Any]:
        total_score = 0.0
        feature_deviations = {}

        for feat, weight in cls.WEIGHTS.items():
            if feat not in baseline or feat not in feature_vector:
                continue

            ref = baseline[feat]
            val = feature_vector[feat]
            std_dev = max(ref["std_dev"], 0.05 * (ref["mean"] if ref["mean"] > 0 else 1.0))
            z = abs(val - ref["mean"]) / std_dev
            penalty = cls.map_z_to_penalty(z)

            total_score += weight * penalty
            feature_deviations[feat] = {
                "observed": val,
                "baseline_mean": ref["mean"],
                "baseline_std_dev": ref["std_dev"],
                "z_score": round(z, 2),
                "penalty": round(penalty, 1)
            }

        final_score = round(min(100.0, max(0.0, total_score)), 1)
        
        # Classification & Confidence
        if final_score >= 75.0:
            severity = "CRITICAL"
            confidence = min(0.98, 0.70 + (final_score / 400.0))
        elif final_score >= 45.0:
            severity = "HIGH"
            confidence = min(0.90, 0.60 + (final_score / 300.0))
        elif final_score >= 20.0:
            severity = "MEDIUM"
            confidence = 0.70
        else:
            severity = "LOW"
            confidence = 0.50

        return {
            "anomaly_score": final_score,
            "severity": severity,
            "confidence": round(confidence, 2),
            "is_anomaly": final_score >= 25.0,
            "deviations": feature_deviations
        }

class NetworkAnomalyDetector:
    def __init__(self, baseline_path: Optional[str] = None):
        self.baseline: Dict[str, Dict[str, float]] = {}
        self.scorer = AnomalyScorer()
        if baseline_path:
            self.load_baseline(baseline_path)

    def train_baseline(self, windows: List[Dict[str, float]]) -> Dict[str, Dict[str, float]]:
        if not windows:
            raise ValueError("Training window set cannot be empty.")

        stats = {}
        features = windows[0].keys()
        for f in features:
            values = [w[f] for w in windows]
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std = math.sqrt(variance)
            stats[f] = {
                "mean": round(mean, 3),
                "std_dev": round(std, 3)
            }
        self.baseline = stats
        return stats

    def evaluate(self, feature_vector: Dict[str, float]) -> Dict[str, Any]:
        if not self.baseline:
            raise RuntimeError("Anomaly detector evaluated before baseline calibration.")
        return self.scorer.compute_composite_score(feature_vector, self.baseline)

    def save_baseline(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.baseline, f, indent=2)

    def load_baseline(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            self.baseline = json.load(f)