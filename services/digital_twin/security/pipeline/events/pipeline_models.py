from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class PipelineStateEnum(str, Enum):
    RECEIVED = "RECEIVED"
    PARSED = "PARSED"
    NORMALIZED = "NORMALIZED"
    FEATURES_EXTRACTED = "FEATURES_EXTRACTED"
    DETECTED = "DETECTED"
    RISK_ASSESSED = "RISK_ASSESSED"
    ALERT_CREATED = "ALERT_CREATED"
    STORED = "STORED"
    FAILED = "FAILED"

class DetectionEvidence(BaseModel):
    ruleOrSignature: str
    observedMetric: str
    observedValue: float
    thresholdValue: float
    confidence: float = 1.0

class PipelineFeatureVector(BaseModel):
    connectionRate: float = 0.0
    packetRate: float = 0.0
    byteRate: float = 0.0
    failedConnections: int = 0
    uniquePorts: int = 0
    protocolRatio: float = 1.0
    windowSeconds: float = 10.0
    metadata: Dict[str, Any] = Field(default_factory=dict)

class PipelineDetectionResult(BaseModel):
    isAnomalyOrThreat: bool = False
    detectionType: str = "BENIGN"
    confidence: float = 0.0
    severity: str = "LOW"
    evidence: List[DetectionEvidence] = Field(default_factory=list)

class PipelineRiskAssessment(BaseModel):
    likelihood: float = 0.1
    impact: float = 1.0
    assetCriticalityMultiplier: float = 1.0
    riskScore: float = 1.0
    riskLevel: str = "LOW"

class ActionableSecurityAlert(BaseModel):
    alertId: str = Field(default_factory=lambda: f"alt-{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: str
    riskScore: float
    detectionSource: str
    sourceDevice: str
    targetDevice: str
    sourceIP: str
    destinationIP: str
    protocol: str
    port: Optional[int] = None
    signature: str
    evidence: List[DetectionEvidence] = Field(default_factory=list)
    twinPostureDegraded: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

class PipelineExecutionContext(BaseModel):
    pipelineRunId: str = Field(default_factory=lambda: f"pipe-{uuid.uuid4().hex[:8]}")
    currentState: PipelineStateEnum = PipelineStateEnum.RECEIVED
    history: List[PipelineStateEnum] = Field(default_factory=lambda: [PipelineStateEnum.RECEIVED])
    rawInput: Any = None
    parsedEvent: Optional[Dict[str, Any]] = None
    normalizedEvent: Optional[Any] = None
    featureVector: Optional[PipelineFeatureVector] = None
    detectionResult: Optional[PipelineDetectionResult] = None
    riskAssessment: Optional[PipelineRiskAssessment] = None
    createdAlert: Optional[ActionableSecurityAlert] = None
    failureReason: Optional[str] = None
    failedAtStage: Optional[str] = None

    def transition_to(self, new_state: PipelineStateEnum):
        self.currentState = new_state
        self.history.append(new_state)

    def mark_failed(self, stage_name: str, reason: str):
        self.currentState = PipelineStateEnum.FAILED
        self.history.append(PipelineStateEnum.FAILED)
        self.failedAtStage = stage_name
        self.failureReason = reason