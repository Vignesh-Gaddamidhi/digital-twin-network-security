import time
import math
from typing import Dict, Any, List, Tuple, Optional
import numpy as np

from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES

class DefensiveValidationError(ValueError):
    """Raised when incoming telemetry violates structural or mathematical constraints."""
    pass

class DefensivePredictionGuard:
    """Sanitizes incoming feature dictionaries and traps catastrophic model failures."""

    @staticmethod
    def sanitize_features(raw_features: Any) -> Dict[str, float]:
        if not isinstance(raw_features, dict):
            raise DefensiveValidationError("Features payload must be a JSON dictionary of numeric key-values.")

        sanitized: Dict[str, float] = {}
        for fn in FEATURE_NAMES:
            val = raw_features.get(fn, 0.0)

            # Check for nulls, NaNs, or non-numeric types
            if val is None:
                val = 0.0
            try:
                flt_val = float(val)
            except (ValueError, TypeError):
                raise DefensiveValidationError(f"Feature '{fn}' contains non-numeric value: {val}")

            if math.isnan(flt_val):
                raise DefensiveValidationError(f"Feature '{fn}' contains illegal NaN value.")
            if math.isinf(flt_val):
                raise DefensiveValidationError(f"Feature '{fn}' contains illegal infinite value.")

            sanitized[fn] = flt_val

        return sanitized

    @staticmethod
    def profile_latency(start_perf: float) -> float:
        return round((time.perf_counter() - start_perf) * 1000, 3)

def sanitize_and_measure_input(raw_features: Any) -> Tuple[Dict[str, float], float]:
    t0 = time.perf_counter()
    sanitized = DefensivePredictionGuard.sanitize_features(raw_features)
    latency_ms = DefensivePredictionGuard.profile_latency(t0)
    return sanitized, latency_ms