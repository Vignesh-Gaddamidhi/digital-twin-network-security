import time
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid

from services.digital_twin.security.pipeline.normalization.canonical_event import CanonicalEvent
from services.digital_twin.security.pipeline.normalization.unified_normalizer import unified_normalizer
from services.digital_twin.security.pipeline.features.feature_definitions import FeatureWindowEnum, SecurityFeatureVector
from services.digital_twin.security.pipeline.features.feature_extractor import feature_extraction_engine
from services.digital_twin.security.pipeline.detection.detection_models import DetectionResult, DetectionTypeEnum
from services.digital_twin.security.pipeline.detection.detection_engine import pipeline_detection_engine
from services.digital_twin.security.pipeline.risk.risk_models import RiskAssessment, RiskLevelEnum
from services.digital_twin.security.pipeline.risk.risk_engine import risk_scoring_engine
from services.digital_twin.security.pipeline.alerts.alert_models import SecurityAlert, AlertStatusEnum, alert_store

from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine

class StageDurations(BaseModel):
    normalizationMs: float = 0.0
    featureExtractionMs: float = 0.0
    detectionMs: float = 0.0
    riskAssessmentMs: float = 0.0
    alertGenerationMs: float = 0.0
    twinUpdateMs: float = 0.0
    totalMs: float = 0.0

class PipelineProcessingResult(BaseModel):
    pipelineRunId: str = Field(default_factory=lambda: f"pipe-{uuid.uuid4().hex[:8]}")
    receivedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    processedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "SUCCESS"  # SUCCESS | REJECTED | ANOMALY_DETECTED | ALERT_GENERATED | FAILED
    errorCode: Optional[str] = None
    errorMessage: Optional[str] = None
    canonicalEvent: Optional[CanonicalEvent] = None
    featureVector: Optional[SecurityFeatureVector] = None
    detection: Optional[DetectionResult] = None
    riskAssessment: Optional[RiskAssessment] = None
    alert: Optional[SecurityAlert] = None
    isDuplicateAlert: bool = False
    durations: StageDurations = Field(default_factory=StageDurations)
    twinPostureUpdated: bool = False
    newTwinPosture: Optional[str] = None

class CompleteSecurityEventPipeline:
    """Master production-grade security event pipeline orchestrating Week 13 capabilities."""

    def __init__(self):
        self.processing_ledger: List[PipelineProcessingResult] = []

    def process(self, raw_input: Dict[str, Any], source_type: Optional[str] = None, window: FeatureWindowEnum = FeatureWindowEnum.WINDOW_5S) -> PipelineProcessingResult:
        res = PipelineProcessingResult()
        t_start = time.perf_counter()

        # 1. Normalization Stage
        t0 = time.perf_counter()
        canon_evt, norm_err = unified_normalizer.normalize(raw_input, source_type=source_type)
        res.durations.normalizationMs = round((time.perf_counter() - t0) * 1000, 3)

        if norm_err or not canon_evt:
            res.status = "REJECTED"
            res.errorCode = "NORMALIZATION_ERROR"
            res.errorMessage = norm_err or "Normalization failed"
            res.durations.totalMs = round((time.perf_counter() - t_start) * 1000, 3)
            self.processing_ledger.append(res)
            return res

        res.canonicalEvent = canon_evt

        # 2. Feature Extraction Stage
        t1 = time.perf_counter()
        try:
            feat_vec = feature_extraction_engine.ingest_and_extract(canon_evt, window=window)
            res.featureVector = feat_vec
        except Exception as e:
            res.status = "FAILED"
            res.errorCode = "FEATURE_EXTRACTION_ERROR"
            res.errorMessage = str(e)
            res.durations.totalMs = round((time.perf_counter() - t_start) * 1000, 3)
            self.processing_ledger.append(res)
            return res
        res.durations.featureExtractionMs = round((time.perf_counter() - t1) * 1000, 3)

        # 3. Detection Stage
        t2 = time.perf_counter()
        try:
            det = pipeline_detection_engine.detect(feat_vec, canon_evt)
            res.detection = det
        except Exception as e:
            res.status = "FAILED"
            res.errorCode = "DETECTION_ERROR"
            res.errorMessage = str(e)
            res.durations.totalMs = round((time.perf_counter() - t_start) * 1000, 3)
            self.processing_ledger.append(res)
            return res
        res.durations.detectionMs = round((time.perf_counter() - t2) * 1000, 3)

        # 4. Risk Assessment Stage
        t3 = time.perf_counter()
        try:
            risk = risk_scoring_engine.assess_risk(det)
            res.riskAssessment = risk
        except Exception as e:
            res.status = "FAILED"
            res.errorCode = "RISK_ASSESSMENT_ERROR"
            res.errorMessage = str(e)
            res.durations.totalMs = round((time.perf_counter() - t_start) * 1000, 3)
            self.processing_ledger.append(res)
            return res
        res.durations.riskAssessmentMs = round((time.perf_counter() - t3) * 1000, 3)

        # 5. Alert Generation Stage
        t4 = time.perf_counter()
        if det.detected and risk.level in (RiskLevelEnum.MEDIUM, RiskLevelEnum.HIGH, RiskLevelEnum.CRITICAL):
            alert = SecurityAlert(
                timestamp=canon_evt.eventTimestamp,
                source=canon_evt.source,
                destination=canon_evt.destination,
                protocol=canon_evt.protocol.value,
                port=canon_evt.port,
                eventType=canon_evt.eventType,
                severity=risk.level.value,
                detectionSource=canon_evt.detectionSource.value,
                detectionType=det.detectionType.value,
                confidence=det.confidence,
                riskScore=risk.score,
                riskLevel=risk.level.value,
                evidence=[e.model_dump() for e in det.evidence],
                affectedDevice=canon_evt.destination,
                status=AlertStatusEnum.NEW
            )
            stored_alert, is_dup = alert_store.add_alert(alert)
            res.isDuplicateAlert = is_dup
            res.alert = alert
            res.status = "ALERT_GENERATED"
        else:
            res.status = "ANOMALY_DETECTED" if det.detected else "SUCCESS"
        res.durations.alertGenerationMs = round((time.perf_counter() - t4) * 1000, 3)

        # 6. Digital Twin Posture Synchronization
        t5 = time.perf_counter()
        if res.alert and not res.isDuplicateAlert and res.alert.affectedDevice != "UNKNOWN_DEVICE":
            target = res.alert.affectedDevice
            new_status = self._apply_twin_state_transition(target, res.alert)
            if new_status:
                res.twinPostureUpdated = True
                res.newTwinPosture = new_status
        res.durations.twinUpdateMs = round((time.perf_counter() - t5) * 1000, 3)

        res.durations.totalMs = round((time.perf_counter() - t_start) * 1000, 3)
        res.processedAt = datetime.now(timezone.utc).isoformat()
        self.processing_ledger.append(res)
        return res

    def _apply_twin_state_transition(self, target_id: str, alert: SecurityAlert) -> Optional[str]:
        """Controlled state progression: NORMAL -> SUSPICIOUS -> UNDER_ATTACK -> COMPROMISED."""
        if not hasattr(security_state_engine, "canTransitionSecurityStatus"):
            return None

        reason = f"Security Alert ({alert.detectionType}): {alert.riskLevel} (Score: {alert.riskScore})"
        target_state = SecurityPostureStatusEnum.SUSPICIOUS

        # Determine target state based on severity and detection type
        if alert.riskLevel == "CRITICAL" or alert.detectionType == "OUTBOUND_VOLUME_ANOMALY":
            target_state = SecurityPostureStatusEnum.COMPROMISED
        elif alert.riskLevel == "HIGH" or alert.detectionType in ("BEACONING_PATTERN", "TRAFFIC_SPIKE"):
            target_state = getattr(SecurityPostureStatusEnum, "UNDER_ATTACK", SecurityPostureStatusEnum.SUSPICIOUS)
        else:
            target_state = SecurityPostureStatusEnum.SUSPICIOUS

        try:
            # 1. Direct transition if allowed
            if security_state_engine.canTransitionSecurityStatus(target_id, target_state):
                security_state_engine.transitionSecurityStatus(target_id, target_state, reason=reason)
                return target_state.value

            # 2. Step through intermediate states
            progression = [
                SecurityPostureStatusEnum.SUSPICIOUS,
                getattr(SecurityPostureStatusEnum, "UNDER_ATTACK", None),
                SecurityPostureStatusEnum.COMPROMISED
            ]
            for step in progression:
                if step and security_state_engine.canTransitionSecurityStatus(target_id, step):
                    security_state_engine.transitionSecurityStatus(target_id, step, reason=reason)
                    if step == target_state:
                        return target_state.value

            # Final check for target
            if security_state_engine.canTransitionSecurityStatus(target_id, target_state):
                security_state_engine.transitionSecurityStatus(target_id, target_state, reason=reason)
                return target_state.value
        except Exception:
            pass

        return None

    def clear(self):
        self.processing_ledger.clear()
        alert_store.clear()
        unified_normalizer.clear()
        feature_extraction_engine.clear()
        pipeline_detection_engine.clear()

complete_security_pipeline = CompleteSecurityEventPipeline()