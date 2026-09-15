from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from frontend.predictions.early_warning_models import (
    EarlyWarningStateEnum, ModelForecastItem, EarlyWarningHistoryRecord,
    EarlyWarningDashboardSnapshot
)

class EarlyWarningDashboardEngine:
    """Manages Phase 14 time-series forecast integration, warning state thresholds, and cooldowns."""

    def __init__(self, cooldown_duration_sec: int = 30):
        self.cooldown_duration_sec = cooldown_duration_sec
        self.active_history: List[EarlyWarningHistoryRecord] = []
        self._seed_default_state()

    def _seed_default_state(self):
        self.active_history.clear()
        now = datetime.now(timezone.utc).isoformat()
        self.active_history = [
            EarlyWarningHistoryRecord(
                warningId="WARN-1001",
                targetDevice="WEB-01",
                firstDetectedAt=now,
                lastUpdatedAt=now,
                consecutiveWarningCount=3,
                cooldownRemainingSec=0,
                status=EarlyWarningStateEnum.EARLY_WARNING,
                leadTimeSeconds=42
            )
        ]

    def determine_warning_state(self, future_prob: float, confidence: float) -> EarlyWarningStateEnum:
        if future_prob >= 0.90 and confidence >= 0.90:
            return EarlyWarningStateEnum.IMPACT_STAGE
        elif future_prob >= 0.85 and confidence >= 0.85:
            return EarlyWarningStateEnum.HIGH_CONFIDENCE_WARNING
        elif future_prob >= 0.75:
            return EarlyWarningStateEnum.EARLY_WARNING
        elif future_prob >= 0.50:
            return EarlyWarningStateEnum.WATCH
        return EarlyWarningStateEnum.NO_WARNING

    def generate_snapshot(
        self,
        target_device: str = "WEB-01",
        current_prob: float = 0.72,
        future_prob: float = 0.87,
        horizon_sec: int = 60,
        lead_time_sec: int = 42
    ) -> EarlyWarningDashboardSnapshot:
        if not (0.0 <= current_prob <= 1.0) or not (0.0 <= future_prob <= 1.0):
            raise ValueError("Probabilities must reside within [0.0, 1.0].")

        status = self.determine_warning_state(future_prob, confidence=0.91)

        # Multi-model evaluation output
        models = [
            ModelForecastItem(modelName="LSTM", architecture="Recurrent", futureThreatProbability=future_prob, confidenceScore=0.91, inferenceLatencyMs=2.1),
            ModelForecastItem(modelName="GRU", architecture="GatedRec", futureThreatProbability=round(max(0.0, future_prob - 0.03), 2), confidenceScore=0.88, inferenceLatencyMs=1.8),
            ModelForecastItem(modelName="Temporal", architecture="SlidingRF", futureThreatProbability=round(max(0.0, future_prob - 0.06), 2), confidenceScore=0.85, inferenceLatencyMs=1.2)
        ]

        # Audit ledger management
        now_ts = datetime.now(timezone.utc).isoformat()
        existing = next((h for h in self.active_history if h.targetDevice == target_device), None)
        if existing:
            existing.lastUpdatedAt = now_ts
            existing.status = status
            existing.leadTimeSeconds = lead_time_sec
            existing.consecutiveWarningCount += 1
            if existing.cooldownRemainingSec > 0:
                existing.cooldownRemainingSec = max(0, existing.cooldownRemainingSec - 5)
        else:
            rec = EarlyWarningHistoryRecord(
                targetDevice=target_device,
                firstDetectedAt=now_ts,
                lastUpdatedAt=now_ts,
                consecutiveWarningCount=1,
                cooldownRemainingSec=self.cooldown_duration_sec,
                status=status,
                leadTimeSeconds=lead_time_sec
            )
            self.active_history.insert(0, rec)

        return EarlyWarningDashboardSnapshot(
            targetDevice=target_device,
            currentThreatProbability=current_prob,
            futureThreatProbability=future_prob,
            predictionHorizonSeconds=horizon_sec,
            leadTimeSeconds=lead_time_sec,
            status=status,
            modelComparisons=models,
            warningHistory=self.active_history
        )

    def trigger_cooldown(self, target_device: str, duration_sec: Optional[int] = None):
        target = next((h for h in self.active_history if h.targetDevice == target_device), None)
        if target:
            target.cooldownRemainingSec = duration_sec or self.cooldown_duration_sec

early_warning_dashboard_engine = EarlyWarningDashboardEngine()