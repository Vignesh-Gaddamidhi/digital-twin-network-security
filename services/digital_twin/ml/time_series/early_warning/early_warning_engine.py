from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
WARNING_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "time_series" / "early_warning"
WARNING_FILE = WARNING_ARTIFACTS_DIR / "warning_records.json"

class EarlyWarningState(str, Enum):
    NO_WARNING = "NO_WARNING"
    WATCH = "WATCH"
    EARLY_WARNING = "EARLY_WARNING"
    HIGH_CONFIDENCE_WARNING = "HIGH_CONFIDENCE_WARNING"
    IMPACT_STAGE = "IMPACT_STAGE"

class EarlyWarningRecord(BaseModel):
    warningId: str = Field(default_factory=lambda: f"WARN-{uuid.uuid4().hex[:8].upper()}")
    deviceId: str
    targetService: str = "TCP/443"
    state: EarlyWarningState
    currentStage: str  # NORMAL, EARLY_INDICATORS, ESCALATION, IMPACT, RECOVERY
    currentThreatProbability: float
    peakThreatProbability: float
    firstDetectedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lastUpdatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    consecutiveDetections: int = 1
    predictedCategory: str = "DOS_LIKE"
    leadTimeEstimateSeconds: float = 35.0
    status: str = "ACTIVE"  # ACTIVE, RESOLVED, COOLED_DOWN
    rationale: str

class EarlyWarningEngine:
    """Detects pre-impact trajectories, manages alert lifecycle, and prevents alert flooding."""

    def __init__(self, cooldown_seconds: float = 30.0):
        self.cooldown_seconds = cooldown_seconds
        WARNING_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        self.active_warnings: Dict[str, EarlyWarningRecord] = {}
        self.history: List[EarlyWarningRecord] = []

    def evaluate_warning_state(
        self,
        threat_probability: float,
        current_stage: str
    ) -> EarlyWarningState:
        stage_up = current_stage.upper()
        if stage_up == "IMPACT":
            return EarlyWarningState.IMPACT_STAGE
        elif threat_probability >= 0.85 or stage_up == "ESCALATION":
            return EarlyWarningState.HIGH_CONFIDENCE_WARNING
        elif threat_probability >= 0.65 or stage_up == "EARLY_INDICATORS":
            return EarlyWarningState.EARLY_WARNING
        elif threat_probability >= 0.40:
            return EarlyWarningState.WATCH
        else:
            return EarlyWarningState.NO_WARNING

    def process_prediction(
        self,
        device_id: str,
        threat_probability: float,
        current_stage: str,
        predicted_category: str = "DOS_LIKE",
        lead_time_seconds: float = 35.0
    ) -> Tuple[EarlyWarningRecord, bool]:
        state = self.evaluate_warning_state(threat_probability, current_stage)
        now_iso = datetime.now(timezone.utc).isoformat()
        is_new_alert = False

        if state == EarlyWarningState.NO_WARNING:
            if device_id in self.active_warnings:
                rec = self.active_warnings.pop(device_id)
                rec.status = "RESOLVED"
                rec.lastUpdatedAt = now_iso
                self._persist_record(rec)
            rec = EarlyWarningRecord(
                deviceId=device_id,
                state=state,
                currentStage=current_stage,
                currentThreatProbability=threat_probability,
                peakThreatProbability=threat_probability,
                status="NORMAL",
                rationale="Normal baseline flow parameters observed."
            )
            return rec, False

        # Anti-Flooding Aggregator
        if device_id in self.active_warnings:
            existing = self.active_warnings[device_id]
            existing.state = state
            existing.currentStage = current_stage
            existing.currentThreatProbability = threat_probability
            existing.peakThreatProbability = max(existing.peakThreatProbability, threat_probability)
            existing.lastUpdatedAt = now_iso
            existing.consecutiveDetections += 1
            existing.leadTimeEstimateSeconds = lead_time_seconds
            existing.rationale = f"Updated warning: {existing.consecutiveDetections} consecutive detections. State={state.value}."
            self._persist_record(existing)
            return existing, False
        else:
            is_new_alert = True
            new_record = EarlyWarningRecord(
                deviceId=device_id,
                state=state,
                currentStage=current_stage,
                currentThreatProbability=threat_probability,
                peakThreatProbability=threat_probability,
                predictedCategory=predicted_category,
                leadTimeEstimateSeconds=lead_time_seconds,
                firstDetectedAt=now_iso,
                lastUpdatedAt=now_iso,
                consecutiveDetections=1,
                status="ACTIVE",
                rationale=f"New early warning triggered for {device_id} at pre-impact stage ({current_stage})."
            )
            self.active_warnings[device_id] = new_record
            self.history.append(new_record)
            self._persist_record(new_record)
            return new_record, True

    def _persist_record(self, record: EarlyWarningRecord):
        existing = []
        if WARNING_FILE.exists():
            try:
                with open(WARNING_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        # Update or append
        updated = False
        for i, item in enumerate(existing):
            if item.get("warningId") == record.warningId:
                existing[i] = record.model_dump()
                updated = True
                break
        if not updated:
            existing.append(record.model_dump())

        existing = existing[-100:]
        with open(WARNING_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.active_warnings.clear()
        self.history.clear()
        if WARNING_FILE.exists():
            try:
                WARNING_FILE.unlink()
            except Exception:
                pass

early_warning_engine = EarlyWarningEngine()