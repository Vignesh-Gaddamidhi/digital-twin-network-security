import math
from typing import Dict, Any, Tuple, Optional, List
import numpy as np

from services.digital_twin.ml.training.dataset_loader import FEATURE_NAMES

class DefensiveSanitizer:
    """Sanitizes incoming telemetry features, validates probabilities, and catches invalid inputs."""

    @staticmethod
    def sanitize_features(raw_features: Any) -> Tuple[bool, np.ndarray, List[str]]:
        errors = []
        if not isinstance(raw_features, dict):
            return False, np.zeros(len(FEATURE_NAMES), dtype=np.float32), ["Features payload must be a key-value dictionary"]

        clean_vector = []
        for fn in FEATURE_NAMES:
            val = raw_features.get(fn, 0.0)
            if val is None:
                errors.append(f"Feature '{fn}' is None; imputed to 0.0")
                clean_vector.append(0.0)
            elif isinstance(val, (int, float)):
                if math.isnan(val):
                    errors.append(f"Feature '{fn}' is NaN; imputed to 0.0")
                    clean_vector.append(0.0)
                elif math.isinf(val):
                    errors.append(f"Feature '{fn}' is Infinite; clamped to 1000.0")
                    clean_vector.append(1000.0 if val > 0 else -1000.0)
                else:
                    clean_vector.append(float(val))
            else:
                try:
                    num_val = float(val)
                    clean_vector.append(num_val)
                except (ValueError, TypeError):
                    errors.append(f"Feature '{fn}' has invalid type {type(val)}; imputed to 0.0")
                    clean_vector.append(0.0)

        return True, np.array(clean_vector, dtype=np.float32), errors

    @staticmethod
    def validate_probability(prob: Any) -> Tuple[bool, float, Optional[str]]:
        if prob is None:
            return False, 0.0, "Probability is None"
        if not isinstance(prob, (int, float)):
            return False, 0.0, f"Probability has invalid type {type(prob)}"
        if math.isnan(prob):
            return False, 0.0, "Probability is NaN"
        if math.isinf(prob):
            return False, 0.0, "Probability is Infinite"
        if prob < 0.0 or prob > 1.0:
            return False, float(np.clip(prob, 0.0, 1.0)), f"Probability {prob} out of bounds [0, 1]; clamped"
        return True, float(prob), None

defensive_sanitizer = DefensiveSanitizer()