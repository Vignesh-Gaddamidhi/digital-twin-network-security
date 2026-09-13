import math
from typing import Dict, Any, List, Tuple
import numpy as np

from services.digital_twin.ml.time_series.features.feature_registry import temporal_feature_registry

TREND_CODES = {
    "STABLE": 0.0,
    "INCREASING": 1.0,
    "DECREASING": 2.0,
    "VOLATILE": 3.0
}

class TemporalFeatureExtractor:
    """Extracts rolling statistics, differencing, volatility, and trend metrics across sequential flows."""

    def __init__(self, lag_depth: int = 3, window_size: int = 3):
        self.lag_depth = lag_depth
        self.window_size = window_size

    @staticmethod
    def calculate_trend(series: List[float], threshold: float = 1.0) -> str:
        """Determines trend state (STABLE, INCREASING, DECREASING, VOLATILE)."""
        if len(series) < 2:
            return "STABLE"

        recent = series[-5:] if len(series) >= 5 else series
        diffs = [recent[i] - recent[i - 1] for i in range(1, len(recent))]

        # Check for alternating volatility
        sign_changes = sum(1 for i in range(1, len(diffs)) if (diffs[i] * diffs[i - 1]) < 0)
        mean_val = float(np.mean(recent))
        std_val = float(np.std(recent))
        cv = (std_val / (abs(mean_val) + 1e-5)) if mean_val != 0 else 0.0

        if sign_changes >= 2 and cv >= 0.40:
            return "VOLATILE"

        latest_diff = diffs[-1]
        if latest_diff > threshold:
            return "INCREASING"
        elif latest_diff < -threshold:
            return "DECREASING"
        else:
            return "STABLE"

    @staticmethod
    def safe_percentage_change(current: float, previous: float) -> float:
        if previous == 0.0:
            return 100.0 if current > 0.0 else 0.0
        return round(((current - previous) / abs(previous)) * 100.0, 2)

    def extract_features(self, chronological_records: List[Dict[str, Any]]) -> List[Dict[str, float]]:
        """Processes raw telemetry list into rich temporal feature dictionaries."""
        if not chronological_records:
            return []

        # Buffer tracking historical raw values
        buffers: Dict[str, List[float]] = {
            "packet_rate": [],
            "bytes": [],
            "failed_connections": [],
            "dns_frequency": [],
            "destination_diversity": []
        }

        feature_matrix: List[Dict[str, float]] = []

        for item in chronological_records:
            pr = float(item.get("packet_rate", 0.0))
            by = float(item.get("bytes", item.get("bytes_per_second", 0.0)))
            fc = float(item.get("failed_connections", 0.0))
            df = float(item.get("dns_frequency", 0.0))
            dd = float(item.get("destination_diversity", 0.0))

            buffers["packet_rate"].append(pr)
            buffers["bytes"].append(by)
            buffers["failed_connections"].append(fc)
            buffers["dns_frequency"].append(df)
            buffers["destination_diversity"].append(dd)

            # 1. Packet Rate Computations
            pr_buf = buffers["packet_rate"]
            pr_lag1 = pr_buf[-2] if len(pr_buf) >= 2 else pr
            pr_lag2 = pr_buf[-3] if len(pr_buf) >= 3 else pr_lag1
            pr_slice = pr_buf[-self.window_size:]
            pr_mean = float(np.mean(pr_slice))
            pr_std = float(np.std(pr_slice)) if len(pr_slice) > 1 else 0.0
            pr_roc = round(pr - pr_lag1, 4)
            pr_pct = self.safe_percentage_change(pr, pr_lag1)
            pr_trend = self.calculate_trend(pr_buf, threshold=2.0)

            # 2. Bytes Computations
            by_buf = buffers["bytes"]
            by_lag1 = by_buf[-2] if len(by_buf) >= 2 else by
            by_slice = by_buf[-self.window_size:]
            by_mean = float(np.mean(by_slice))
            by_roc = round(by - by_lag1, 4)

            # 3. Failed Connections Computations
            fc_buf = buffers["failed_connections"]
            fc_slice = fc_buf[-self.window_size:]
            fc_mean = float(np.mean(fc_slice))
            fc_lag1 = fc_buf[-2] if len(fc_buf) >= 2 else fc
            fc_roc = round(fc - fc_lag1, 4)

            # 4. DNS Frequency Computations
            df_buf = buffers["dns_frequency"]
            df_slice = df_buf[-self.window_size:]
            df_mean = float(np.mean(df_slice))

            # 5. Destination Diversity Computations
            dd_buf = buffers["destination_diversity"]
            dd_trend = self.calculate_trend(dd_buf, threshold=0.1)

            features = {
                "packet_rate": round(pr, 4),
                "packet_rate_lag_1": round(pr_lag1, 4),
                "packet_rate_lag_2": round(pr_lag2, 4),
                "packet_rate_rolling_mean_w3": round(pr_mean, 4),
                "packet_rate_rolling_std_w3": round(pr_std, 4),
                "packet_rate_rate_of_change": pr_roc,
                "packet_rate_percentage_change": pr_pct,
                "packet_rate_trend": TREND_CODES.get(pr_trend, 0.0),

                "bytes_val": round(by, 4),
                "bytes_lag_1": round(by_lag1, 4),
                "bytes_rolling_mean_w3": round(by_mean, 4),
                "bytes_rate_of_change": by_roc,

                "failed_connections_val": round(fc, 4),
                "failed_connections_rolling_mean_w3": round(fc_mean, 4),
                "failed_connections_rate_of_change": fc_roc,

                "dns_frequency_val": round(df, 4),
                "dns_frequency_rolling_mean_w3": round(df_mean, 4),

                "destination_diversity_val": round(dd, 4),
                "destination_diversity_trend": TREND_CODES.get(dd_trend, 0.0)
            }
            feature_matrix.append(features)

        return feature_matrix

temporal_feature_extractor = TemporalFeatureExtractor()