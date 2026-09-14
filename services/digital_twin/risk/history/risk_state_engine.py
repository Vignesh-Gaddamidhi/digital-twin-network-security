import json
import math
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[4]
RISK_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "risk_engine"
HISTORY_FILE = RISK_ARTIFACTS_DIR / "risk_history.json"
EVENTS_FILE = RISK_ARTIFACTS_DIR / "risk_events.json"

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.risk.history.risk_trend_models import (
    RiskTrendDirection, RiskEventType, RiskHistoryObservation,
    RiskTransitionEvent, DeviceContinuousRiskState, NetworkRiskAggregation
)

class RiskStateEngine:
    """Maintains continuous temporal risk state, trends, transition events, and network aggregation."""

    TIER_ORDER = {
        RiskLevelTier.LOW: 1,
        RiskLevelTier.MEDIUM: 2,
        RiskLevelTier.HIGH: 3,
        RiskLevelTier.CRITICAL: 4
    }

    def __init__(self, artifacts_dir: Path = RISK_ARTIFACTS_DIR, cooldown_seconds: float = 30.0):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.cooldown_seconds = cooldown_seconds
        self.device_states: Dict[str, DeviceContinuousRiskState] = {}
        self.event_history: List[RiskTransitionEvent] = []
        self._last_event_timestamps: Dict[str, float] = {}

    @staticmethod
    def calculate_trend(scores: List[float]) -> RiskTrendDirection:
        if len(scores) < 3:
            return RiskTrendDirection.UNKNOWN

        arr = np.array(scores, dtype=np.float32)
        delta_total = float(arr[-1] - arr[0])
        std = float(np.std(arr))

        # Check consecutive step diffs
        diffs = np.diff(arr)
        pos_steps = np.sum(diffs > 0)
        neg_steps = np.sum(diffs < 0)

        if delta_total >= 10.0 and pos_steps >= len(diffs) * 0.65:
            return RiskTrendDirection.INCREASING
        elif delta_total <= -10.0 and neg_steps >= len(diffs) * 0.65:
            return RiskTrendDirection.DECREASING
        elif abs(delta_total) < 10.0 and std < 6.0:
            return RiskTrendDirection.STABLE
        else:
            return RiskTrendDirection.VOLATILE

    def record_risk_observation(
        self,
        device_id: str,
        risk_score: float,
        prediction_id: str,
        explanation_id: Optional[str] = None
    ) -> Tuple[DeviceContinuousRiskState, List[RiskTransitionEvent]]:
        d_id = device_id.strip()
        score = round(float(risk_score), 2)
        tier = threshold_classifier.classify(score)
        now_ts = datetime.now(timezone.utc).isoformat()
        now_epoch = datetime.now(timezone.utc).timestamp()

        obs = RiskHistoryObservation(
            riskScore=score,
            riskLevel=tier,
            predictionId=prediction_id,
            explanationId=explanation_id,
            timestamp=now_ts
        )

        generated_events: List[RiskTransitionEvent] = []

        if d_id not in self.device_states:
            # Initial Observation
            state = DeviceContinuousRiskState(
                deviceId=d_id,
                currentRiskScore=score,
                currentRiskLevel=tier,
                riskTrend=RiskTrendDirection.UNKNOWN,
                consecutiveObservations=1,
                lastAssessmentAt=now_ts,
                history=[obs]
            )
            self.device_states[d_id] = state
        else:
            state = self.device_states[d_id]
            prev_tier = state.currentRiskLevel
            prev_score = state.currentRiskScore
            score_delta = round(score - prev_score, 2)

            state.history.append(obs)
            state.history = state.history[-50:]  # Preserve last 50 observations
            state.currentRiskScore = score
            state.currentRiskLevel = tier
            state.lastAssessmentAt = now_ts
            state.consecutiveObservations += 1

            # Compute Trend across sliding history (up to last 10 points)
            recent_scores = [h.riskScore for h in state.history[-10:]]
            state.riskTrend = self.calculate_trend(recent_scores)

            # Evaluate State Transitions
            prev_rank = self.TIER_ORDER[prev_tier]
            curr_rank = self.TIER_ORDER[tier]

            # Cooldown suppression check
            last_ts = self._last_event_timestamps.get(d_id, 0.0)
            in_cooldown = (now_epoch - last_ts) < self.cooldown_seconds

            # Event 1: Spike Check
            if score_delta >= 25.0:
                ev_spike = RiskTransitionEvent(
                    deviceId=d_id,
                    eventType=RiskEventType.RISK_SCORE_SPIKE,
                    previousRiskLevel=prev_tier,
                    currentRiskLevel=tier,
                    previousScore=prev_score,
                    currentScore=score,
                    scoreDelta=score_delta,
                    rationale=f"Risk score spiked by +{score_delta:.2f} points ({prev_score:.2f} -> {score:.2f}) on {d_id}."
                )
                generated_events.append(ev_spike)

            # Event 2: Escalation (LOW -> MED -> HIGH -> CRIT)
            if curr_rank > prev_rank:
                ev_esc = RiskTransitionEvent(
                    deviceId=d_id,
                    eventType=RiskEventType.RISK_LEVEL_INCREASED,
                    previousRiskLevel=prev_tier,
                    currentRiskLevel=tier,
                    previousScore=prev_score,
                    currentScore=score,
                    scoreDelta=score_delta,
                    rationale=f"Risk escalated: {prev_tier.value} -> {tier.value} on {d_id}."
                )
                generated_events.append(ev_esc)

                if tier == RiskLevelTier.CRITICAL:
                    generated_events.append(RiskTransitionEvent(
                        deviceId=d_id,
                        eventType=RiskEventType.CRITICAL_RISK_REACHED,
                        previousRiskLevel=prev_tier,
                        currentRiskLevel=tier,
                        previousScore=prev_score,
                        currentScore=score,
                        scoreDelta=score_delta,
                        rationale=f"Critical operational risk threshold breached on asset {d_id}."
                    ))
                elif tier == RiskLevelTier.HIGH:
                    generated_events.append(RiskTransitionEvent(
                        deviceId=d_id,
                        eventType=RiskEventType.HIGH_RISK_REACHED,
                        previousRiskLevel=prev_tier,
                        currentRiskLevel=tier,
                        previousScore=prev_score,
                        currentScore=score,
                        scoreDelta=score_delta,
                        rationale=f"High risk threshold entered for asset {d_id}."
                    ))

            # Event 3: De-escalation / Recovery (CRIT -> HIGH -> MED -> LOW)
            elif curr_rank < prev_rank:
                ev_rec = RiskTransitionEvent(
                    deviceId=d_id,
                    eventType=RiskEventType.RISK_LEVEL_DECREASED,
                    previousRiskLevel=prev_tier,
                    currentRiskLevel=tier,
                    previousScore=prev_score,
                    currentScore=score,
                    scoreDelta=score_delta,
                    rationale=f"Risk mitigated / recovered: {prev_tier.value} -> {tier.value} on {d_id}."
                )
                generated_events.append(ev_rec)

            # Filter duplicates if in cooldown
            if in_cooldown and generated_events:
                for ev in generated_events:
                    ev.cooldownActive = True
            elif generated_events:
                self._last_event_timestamps[d_id] = now_epoch

            self.event_history.extend(generated_events)

        self._persist_state()
        return state, generated_events

    def aggregate_network_risk(self, strategy: str = "MAX", top_n: int = 3) -> NetworkRiskAggregation:
        if not self.device_states:
            return NetworkRiskAggregation(
                strategy=strategy,
                networkRiskScore=0.0,
                networkRiskLevel=RiskLevelTier.LOW,
                highestRiskDevice="NONE",
                monitoredDeviceCount=0,
                criticalDeviceCount=0,
                highDeviceCount=0,
                deviceScores={}
            )

        device_scores = {k: v.currentRiskScore for k, v in self.device_states.items()}
        strat_upper = strategy.upper()

        if strat_upper == "MAX":
            highest_dev = max(device_scores, key=device_scores.get)
            net_score = device_scores[highest_dev]
        elif strat_upper == "TOP_N":
            sorted_scores = sorted(device_scores.values(), reverse=True)[:top_n]
            net_score = float(np.mean(sorted_scores))
            highest_dev = max(device_scores, key=device_scores.get)
        elif strat_upper == "WEIGHTED_AVERAGE":
            net_score = float(np.mean(list(device_scores.values())))
            highest_dev = max(device_scores, key=device_scores.get)
        else:
            highest_dev = max(device_scores, key=device_scores.get)
            net_score = device_scores[highest_dev]

        net_score = round(net_score, 2)
        net_level = threshold_classifier.classify(net_score)

        crit_count = sum(1 for v in self.device_states.values() if v.currentRiskLevel == RiskLevelTier.CRITICAL)
        high_count = sum(1 for v in self.device_states.values() if v.currentRiskLevel == RiskLevelTier.HIGH)

        return NetworkRiskAggregation(
            strategy=strat_upper,
            networkRiskScore=net_score,
            networkRiskLevel=net_level,
            highestRiskDevice=highest_dev,
            monitoredDeviceCount=len(self.device_states),
            criticalDeviceCount=crit_count,
            highDeviceCount=high_count,
            deviceScores=device_scores
        )

    def _persist_state(self):
        data = {k: v.model_dump() for k, v in self.device_states.items()}
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        ev_data = [e.model_dump() for e in self.event_history[-100:]]
        with open(EVENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(ev_data, f, indent=2)

    def clear(self):
        self.device_states.clear()
        self.event_history.clear()
        self._last_event_timestamps.clear()
        if HISTORY_FILE.exists():
            try:
                HISTORY_FILE.unlink()
            except Exception:
                pass
        if EVENTS_FILE.exists():
            try:
                EVENTS_FILE.unlink()
            except Exception:
                pass

risk_state_engine = RiskStateEngine()