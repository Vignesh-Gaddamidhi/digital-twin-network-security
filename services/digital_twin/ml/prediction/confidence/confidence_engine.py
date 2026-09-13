import math
from typing import Dict, Any, List, Tuple
from services.digital_twin.ml.prediction.confidence.confidence_models import (
    ConfidenceTierEnum, ConfidenceThresholdConfig, ConfidenceAuditReport
)

class PredictionConfidenceEngine:
    """Evaluates prediction certainty using entropy, separation margin, and configurable thresholds."""

    def __init__(self, config: ConfidenceThresholdConfig = ConfidenceThresholdConfig()):
        self.config = config

    def calculate_normalized_entropy(self, probabilities: List[float]) -> float:
        valid_probs = [p for p in probabilities if p > 1e-9]
        if not valid_probs or len(probabilities) <= 1:
            return 0.0

        entropy = -sum(p * math.log2(p) for p in valid_probs)
        max_entropy = math.log2(len(probabilities))
        return round(max(0.0, min(1.0, entropy / max_entropy)), 4)

    def evaluate_confidence(self, class_distribution: Dict[str, float]) -> ConfidenceAuditReport:
        if not class_distribution:
            raise ValueError("Class distribution cannot be empty")

        sorted_dist = sorted(class_distribution.items(), key=lambda item: item[1], reverse=True)
        top_cat, top_prob = sorted_dist[0]

        if len(sorted_dist) > 1:
            runner_up_cat, runner_up_prob = sorted_dist[1]
            margin = round(top_prob - runner_up_prob, 4)
        else:
            runner_up_cat = "NONE"
            margin = top_prob

        prob_values = [v for _, v in sorted_dist]
        norm_entropy = self.calculate_normalized_entropy(prob_values)

        # Tier Decision Logic
        if (
            top_prob >= self.config.highConfidenceThreshold and
            margin >= self.config.highSeparationMargin and
            norm_entropy <= self.config.maxNormalizedEntropyForHigh
        ):
            tier = ConfidenceTierEnum.HIGH_CONFIDENCE
            warning = False
            rationale = f"Decisive prediction for {top_cat} with margin {margin} and low entropy {norm_entropy}."
        elif (
            top_prob >= self.config.mediumConfidenceThreshold and
            margin >= self.config.mediumSeparationMargin
        ):
            tier = ConfidenceTierEnum.MEDIUM_CONFIDENCE
            warning = False
            rationale = f"Moderate certainty for {top_cat}. Secondary candidate {runner_up_cat} observed."
        else:
            tier = ConfidenceTierEnum.LOW_CONFIDENCE
            warning = True
            rationale = f"Low confidence prediction. Top class {top_cat} has high uncertainty (margin={margin}, entropy={norm_entropy})."

        return ConfidenceAuditReport(
            categoryConfidence=round(top_prob, 4),
            confidenceTier=tier,
            topCategory=top_cat,
            runnerUpCategory=runner_up_cat,
            separationMargin=margin,
            normalizedEntropy=norm_entropy,
            isLowConfidenceWarning=warning,
            rationale=rationale
        )

prediction_confidence_engine = PredictionConfidenceEngine()