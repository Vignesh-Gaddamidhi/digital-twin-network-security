import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List

from services.digital_twin.security.pipeline.events.pipeline_models import (
    PipelineStateEnum, PipelineExecutionContext, PipelineFeatureVector,
    PipelineDetectionResult, PipelineRiskAssessment, ActionableSecurityAlert,
    DetectionEvidence
)
from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, EventSourceEnum, SecurityEventTypeEnum, NormalizedSecuritySeverityEnum
)
from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.ids.processor.device_resolver import twin_device_resolver

# --- STAGE INTERFACES ---

class BasePipelineStage(ABC):
    @property
    @abstractmethod
    def stage_name(self) -> str:
        pass

    @abstractmethod
    def execute(self, ctx: PipelineExecutionContext) -> bool:
        pass

# 1. Ingestion Stage
class IngestionStage(BasePipelineStage):
    @property
    def stage_name(self) -> str:
        return "INGESTION"

    def execute(self, ctx: PipelineExecutionContext) -> bool:
        raw = ctx.rawInput
        if not raw:
            ctx.mark_failed(self.stage_name, "Empty input payload")
            return False

        if isinstance(raw, dict):
            ctx.parsedEvent = raw
        elif isinstance(raw, str):
            try:
                ctx.parsedEvent = json.loads(raw.strip())
            except Exception as e:
                ctx.mark_failed(self.stage_name, f"JSON parse error: {str(e)}")
                return False
        elif hasattr(raw, "model_dump"):
            ctx.parsedEvent = raw.model_dump()
        else:
            ctx.mark_failed(self.stage_name, "Unsupported raw payload type")
            return False

        ctx.transition_to(PipelineStateEnum.PARSED)
        return True

# 2. Normalization Stage
class NormalizationStage(BasePipelineStage):
    @property
    def stage_name(self) -> str:
        return "NORMALIZATION"

    def execute(self, ctx: PipelineExecutionContext) -> bool:
        rec = ctx.parsedEvent
        if not rec:
            ctx.mark_failed(self.stage_name, "Missing parsed event")
            return False

        src_ip = rec.get("src_ip") or rec.get("id.orig_h") or rec.get("sourceIP", "0.0.0.0")
        dst_ip = rec.get("dest_ip") or rec.get("id.resp_h") or rec.get("destinationIP", "0.0.0.0")
        src_p = rec.get("src_port") or rec.get("id.orig_p") or rec.get("sourcePort")
        dst_p = rec.get("dest_port") or rec.get("id.resp_p") or rec.get("destinationPort")
        proto = str(rec.get("proto") or rec.get("protocol", "TCP")).upper()

        src_dev = twin_device_resolver.resolve(src_ip, src_p, proto)
        dst_dev = twin_device_resolver.resolve(dst_ip, dst_p, proto)

        raw_source = rec.get("source", "SIMULATION").upper()
        source_enum = getattr(EventSourceEnum, raw_source, EventSourceEnum.SIMULATION)
        if "alert" in rec:
            source_enum = EventSourceEnum.SURICATA
        elif "conn_state" in rec:
            source_enum = EventSourceEnum.ZEEK

        evt_type = SecurityEventTypeEnum.ALERT if ("alert" in rec or rec.get("eventType") == "ALERT") else SecurityEventTypeEnum.FLOW
        severity = NormalizedSecuritySeverityEnum.HIGH if ("alert" in rec or rec.get("severity") in ("HIGH", "CRITICAL")) else NormalizedSecuritySeverityEnum.LOW

        sig = "Observed Flow Telemetry"
        if isinstance(rec.get("alert"), dict):
            sig = rec["alert"].get("signature", sig)
        elif rec.get("signature"):
            sig = rec["signature"]

        norm = NormalizedSecurityEvent(
            source=source_enum,
            eventType=evt_type,
            timestamp=rec.get("timestamp"),
            sourceDevice=src_dev,
            destinationDevice=dst_dev,
            sourceIP=src_ip,
            destinationIP=dst_ip,
            sourcePort=src_p,
            destinationPort=dst_p,
            protocol=proto,
            bytes=int(rec.get("bytes") or 0),
            packets=int(rec.get("packets") or 1),
            application=rec.get("application"),
            severity=severity,
            signature=sig,
            rawReference=rec
        )
        ctx.normalizedEvent = norm
        ctx.transition_to(PipelineStateEnum.NORMALIZED)
        return True

# 3. Feature Extraction Stage
class FeatureExtractionStage(BasePipelineStage):
    @property
    def stage_name(self) -> str:
        return "FEATURE_EXTRACTION"

    def execute(self, ctx: PipelineExecutionContext) -> bool:
        norm: NormalizedSecurityEvent = ctx.normalizedEvent
        if not norm:
            ctx.mark_failed(self.stage_name, "Missing normalized event")
            return False

        failed = 1 if (norm.protocol == "TCP" and norm.rawReference.get("conn_state") == "S0") else 0
        uniq = 1 if norm.destinationPort else 0

        vec = PipelineFeatureVector(
            connectionRate=1.0,
            packetRate=float(norm.packets),
            byteRate=float(norm.bytes),
            failedConnections=failed,
            uniquePorts=uniq,
            protocolRatio=1.0
        )
        ctx.featureVector = vec
        ctx.transition_to(PipelineStateEnum.FEATURES_EXTRACTED)
        return True

# 4. Detection Stage
class DetectionStage(BasePipelineStage):
    @property
    def stage_name(self) -> str:
        return "DETECTION"

    def execute(self, ctx: PipelineExecutionContext) -> bool:
        norm: NormalizedSecurityEvent = ctx.normalizedEvent
        vec: PipelineFeatureVector = ctx.featureVector

        is_threat = False
        det_type = "BENIGN"
        confidence = 0.0
        sev = "LOW"
        evidence_list = []

        if norm.eventType == SecurityEventTypeEnum.ALERT:
            is_threat = True
            det_type = "SIGNATURE_IDS_MATCH"
            confidence = norm.confidence
            sev = norm.severity.value
            evidence_list.append(DetectionEvidence(
                ruleOrSignature=norm.signature,
                observedMetric="ids_alert",
                observedValue=1.0,
                thresholdValue=1.0,
                confidence=confidence
            ))
        elif vec.failedConnections > 0 or norm.bytes > 200000:
            is_threat = True
            det_type = "ANOMALOUS_HEURISTIC"
            confidence = 0.85
            sev = "HIGH" if norm.bytes > 200000 else "MEDIUM"
            evidence_list.append(DetectionEvidence(
                ruleOrSignature="THRESHOLD_SPIKE",
                observedMetric="byte_or_failure_volume",
                observedValue=float(norm.bytes),
                thresholdValue=200000.0,
                confidence=0.85
            ))

        ctx.detectionResult = PipelineDetectionResult(
            isAnomalyOrThreat=is_threat,
            detectionType=det_type,
            confidence=confidence,
            severity=sev,
            evidence=evidence_list
        )
        ctx.transition_to(PipelineStateEnum.DETECTED)
        return True

# 5. Risk Calculation Stage
class RiskEngineStage(BasePipelineStage):
    @property
    def stage_name(self) -> str:
        return "RISK_CALCULATION"

    def execute(self, ctx: PipelineExecutionContext) -> bool:
        det: PipelineDetectionResult = ctx.detectionResult
        norm: NormalizedSecurityEvent = ctx.normalizedEvent

        if not det.isAnomalyOrThreat:
            ctx.riskAssessment = PipelineRiskAssessment(
                likelihood=0.1, impact=1.0, assetCriticalityMultiplier=1.0, riskScore=1.0, riskLevel="LOW"
            )
        else:
            likelihood = det.confidence
            impact_map = {"LOW": 2.0, "MEDIUM": 5.0, "HIGH": 8.0, "CRITICAL": 10.0}
            base_impact = impact_map.get(det.severity, 5.0)

            crit = 1.0
            dst = norm.destinationDevice or ""
            if "db" in dst.lower():
                crit = 1.5
            elif "srv" in dst.lower() or "web" in dst.lower():
                crit = 1.2

            score = round(min(100.0, likelihood * base_impact * crit * 10.0), 1)
            level = "LOW"
            if score >= 75.0:
                level = "CRITICAL"
            elif score >= 50.0:
                level = "HIGH"
            elif score >= 25.0:
                level = "MEDIUM"

            ctx.riskAssessment = PipelineRiskAssessment(
                likelihood=likelihood,
                impact=base_impact,
                assetCriticalityMultiplier=crit,
                riskScore=score,
                riskLevel=level
            )

        ctx.transition_to(PipelineStateEnum.RISK_ASSESSED)
        return True

# 6. Alert Creation Stage
class AlertGenerationStage(BasePipelineStage):
    @property
    def stage_name(self) -> str:
        return "ALERT_CREATION"

    def execute(self, ctx: PipelineExecutionContext) -> bool:
        det: PipelineDetectionResult = ctx.detectionResult
        norm: NormalizedSecurityEvent = ctx.normalizedEvent
        risk: PipelineRiskAssessment = ctx.riskAssessment

        if det.isAnomalyOrThreat:
            alert = ActionableSecurityAlert(
                severity=risk.riskLevel,
                riskScore=risk.riskScore,
                detectionSource=norm.source.value,
                sourceDevice=norm.sourceDevice or "UNKNOWN_DEVICE",
                targetDevice=norm.destinationDevice or "UNKNOWN_DEVICE",
                sourceIP=norm.sourceIP,
                destinationIP=norm.destinationIP,
                protocol=norm.protocol,
                port=norm.destinationPort,
                signature=norm.signature,
                evidence=det.evidence
            )
            ctx.createdAlert = alert
            ctx.transition_to(PipelineStateEnum.ALERT_CREATED)
        else:
            ctx.createdAlert = None
            ctx.transition_to(PipelineStateEnum.ALERT_CREATED)
        return True

# 7. Persistence & Digital Twin State Update Stage
class PersistenceStage(BasePipelineStage):
    @property
    def stage_name(self) -> str:
        return "PERSISTENCE"

    def execute(self, ctx: PipelineExecutionContext) -> bool:
        alert: Optional[ActionableSecurityAlert] = ctx.createdAlert
        if alert and alert.targetDevice != "UNKNOWN_DEVICE":
            target = alert.targetDevice
            if alert.severity in ("CRITICAL", "HIGH"):
                try:
                    reason = f"Pipeline Alert: {alert.signature} ({alert.detectionSource})"
                    if hasattr(security_state_engine, "canTransitionSecurityStatus"):
                        if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED):
                            security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED, reason=reason)
                        else:
                            for intermediate in [SecurityPostureStatusEnum.SUSPICIOUS, getattr(SecurityPostureStatusEnum, "UNDER_ATTACK", None)]:
                                if intermediate and security_state_engine.canTransitionSecurityStatus(target, intermediate):
                                    security_state_engine.transitionSecurityStatus(target, intermediate, reason=reason)
                                    break
                            if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED):
                                security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED, reason=reason)
                    alert.twinPostureDegraded = True
                except Exception:
                    pass

        ctx.transition_to(PipelineStateEnum.STORED)
        return True

# --- PIPELINE ORCHESTRATOR ---

class SecurityEventPipeline:
    """Master orchestrator executing the Day 85 security event pipeline stages."""

    def __init__(self):
        self.stages: List[BasePipelineStage] = [
            IngestionStage(),
            NormalizationStage(),
            FeatureExtractionStage(),
            DetectionStage(),
            RiskEngineStage(),
            AlertGenerationStage(),
            PersistenceStage()
        ]
        self.alert_store: List[ActionableSecurityAlert] = []

    def process(self, raw_input: Any) -> PipelineExecutionContext:
        ctx = PipelineExecutionContext(rawInput=raw_input)

        for stage in self.stages:
            success = stage.execute(ctx)
            if not success or ctx.currentState == PipelineStateEnum.FAILED:
                break

        if ctx.createdAlert:
            self.alert_store.append(ctx.createdAlert)

        return ctx

    def clear(self):
        self.alert_store.clear()

security_event_pipeline = SecurityEventPipeline()