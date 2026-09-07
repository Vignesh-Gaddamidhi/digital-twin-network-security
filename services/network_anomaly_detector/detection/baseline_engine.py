import json
import math
from typing import Dict, Any, List, Optional
from pathlib import Path

class StatisticalBaselineEngine:
    """Manages training baselines (mean, stddev) and evaluates statistical deviations (Z-scores)."""

    def __init__(self, config_path: Optional[str] = None):
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        self.is_calibrated = False
        if config_path and Path(config_path).exists():
            self.load_baseline(config_path)

    def train_baseline(self, observation_windows: List[Dict[str, float]]) -> Dict[str, Dict[str, float]]:
        if not observation_windows:
            raise ValueError("Cannot train baseline on empty observation set.")

        feature_names = observation_windows[0].keys()
        stats = {}

        for feat in feature_names:
            values = [w[feat] for w in observation_windows]
            mean_val = sum(values) / len(values)
            variance = sum((x - mean_val) ** 2 for x in values) / len(values)
            std_dev = math.sqrt(variance)

            # Prevent zero division by enforcing a floor std_dev
            std_dev = max(std_dev, 0.05 * (mean_val if mean_val > 0 else 1.0))

            stats[feat] = {
                "mean": round(mean_val, 3),
                "std_dev": round(std_dev, 3),
                "max_observed": max(values),
                "min_observed": min(values)
            }

        self.baseline_stats = stats
        self.is_calibrated = True
        return stats

    def evaluate_vector(self, current_vector: Dict[str, float], z_threshold: float = 3.0) -> List[Dict[str, Any]]:
        """Compares current observation against baseline and returns triggered anomalies."""
        if not self.is_calibrated:
            return []

        anomalies = []
        for feat, val in current_vector.items():
            if feat not in self.baseline_stats:
                continue

            ref = self.baseline_stats[feat]
            z_score = abs(val - ref["mean"]) / ref["std_dev"]

            if z_score > z_threshold:
                anomalies.append({
                    "feature": feat,
                    "observed_value": val,
                    "baseline_mean": ref["mean"],
                    "baseline_std_dev": ref["std_dev"],
                    "z_score": round(z_score, 2),
                    "severity": "CRITICAL" if z_score > 5.0 else "HIGH"
                })

        return anomalies

    def save_baseline(self, filepath: str):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.baseline_stats, f, indent=2)

    def load_baseline(self, filepath: str):
        with open(filepath, "r", encoding="utf-8") as f:
            self.baseline_stats = json.load(f)
        self.is_calibrated = True