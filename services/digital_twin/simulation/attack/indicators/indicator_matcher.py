from typing import List, Dict
from packages.shared_types.src.attack_indicators import (
    ExpectedIndicatorModel, ObservedIndicatorModel,
    IndicatorVerificationReport, IndicatorDirectionEnum
)
from packages.shared_types.src.protocol_traffic import UnifiedTrafficEventModel
from services.digital_twin.simulation.attack.indicators.indicator_evaluator import indicator_evaluator

class IndicatorMatcher:
    """Matches observable simulation telemetry against scenario expected indicators."""

    @staticmethod
    def compare(
        expected: ExpectedIndicatorModel,
        observed_value: float
    ) -> bool:
        dir_type = expected.direction
        thresh = expected.threshold

        if dir_type == IndicatorDirectionEnum.GREATER_THAN:
            return observed_value > thresh
        elif dir_type == IndicatorDirectionEnum.LESS_THAN:
            return observed_value < thresh
        elif dir_type == IndicatorDirectionEnum.EQUALS:
            return abs(observed_value - thresh) < 1e-5
        return False

    def verify_scenario_indicators(
        self,
        scenario_id: str,
        expected_indicators: List[ExpectedIndicatorModel],
        events: List[UnifiedTrafficEventModel],
        duration_seconds: float = 1.0
    ) -> IndicatorVerificationReport:
        metrics = indicator_evaluator.extract_metrics(events, duration_seconds)

        matched: List[ObservedIndicatorModel] = []
        missed: List[ExpectedIndicatorModel] = []

        for exp in expected_indicators:
            obs_val = metrics.get(exp.metric, 0.0)
            is_matched = self.compare(exp, obs_val)

            if is_matched:
                matched.append(ObservedIndicatorModel(
                    type=exp.type,
                    metric=exp.metric,
                    observedValue=obs_val,
                    matchedThreshold=exp.threshold,
                    direction=exp.direction,
                    severity=getattr(exp, "severity", "MEDIUM"),
                    confidence=exp.confidence,
                    details={"extractedMetrics": metrics}
                ))
            else:
                missed.append(exp)

        total_exp = len(expected_indicators)
        matched_cnt = len(matched)
        precision = (matched_cnt / total_exp) if total_exp > 0 else 1.0

        return IndicatorVerificationReport(
            scenarioId=scenario_id,
            totalExpected=total_exp,
            totalObserved=len(metrics),
            matchedCount=matched_cnt,
            missedCount=len(missed),
            precisionScore=round(precision, 2),
            matchedIndicators=matched,
            missedExpectedIndicators=missed
        )

indicator_matcher = IndicatorMatcher()