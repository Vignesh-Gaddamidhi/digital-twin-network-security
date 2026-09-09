from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from packages.shared_types.src.preconditions import PreconditionRuleModel
from datetime import datetime, timezone
import uuid

class AttackScenarioStateEnum(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    READY = "READY"
    RUNNING = "RUNNING"
    DETECTED = "DETECTED"
    RECOVERING = "RECOVERING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class AttackScenarioSeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackScenarioCategoryEnum(str, Enum):
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    DOS = "DOS"
    SUSPICIOUS_DNS = "SUSPICIOUS_DNS"
    BEACONING = "BEACONING"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"

class ScenarioPrecondition(BaseModel):
    preconditionId: str = Field(default_factory=lambda: f"pre-{uuid.uuid4().hex[:6]}")
    targetDevice: str
    targetOnline: bool = True
    requiredOpenPorts: List[int] = Field(default_factory=list)
    requiredClosedPorts: List[int] = Field(default_factory=list)
    networkReachabilityRequired: bool = True
    description: str = "Precondition checklist"

class ExpectedIndicator(BaseModel):
    indicatorId: str = Field(default_factory=lambda: f"ind-{uuid.uuid4().hex[:6]}")
    indicatorType: str = "VOLUMETRIC_SPIKE"  # e.g., AUTH_FAIL_SURGE, PORT_SPREAD, DNS_ENTROPY
    thresholdMetric: str = "packets_per_second"
    expectedThreshold: float
    direction: str = "GREATER_THAN"
    description: str

class ScenarioTrafficPattern(BaseModel):
    patternType: str = "BURST"  # BURST, SWEEP, FLAP, LOW_AND_SLOW, EXFIL_STREAM
    protocol: str = "TCP"
    intensityMultiplier: float = Field(default=1.0, ge=0.1, le=100.0)
    parameters: Dict[str, Any] = Field(default_factory=dict)

class ScenarioRecoveryConfig(BaseModel):
    autoRecover: bool = True
    recoveryDurationSeconds: int = Field(default=5, ge=1)
    resetSocketConnections: bool = True
    restoreTraffic: bool = True
    restoreNormalTraffic: bool = True
    revertPortMutations: bool = True

class AttackScenarioModel(BaseModel):
    scenarioId: str = Field(..., min_length=4, description="Standardized ID (e.g. SCN-PORTSCAN-001)")
    name: str = Field(..., min_length=2)
    category: AttackScenarioCategoryEnum
    description: str
    sourceDevice: str = "client-01"
    targetDevice: str = "web-01"
    severity: AttackScenarioSeverityEnum = AttackScenarioSeverityEnum.MEDIUM
    durationSeconds: int = Field(default=15, ge=1, le=3600)
    preconditions: ScenarioPrecondition
    preconditionRules: List[PreconditionRuleModel] = Field(default_factory=list)
    trafficPattern: ScenarioTrafficPattern
    expectedIndicators: List[ExpectedIndicator] = Field(default_factory=list)
    recovery: ScenarioRecoveryConfig = Field(default_factory=ScenarioRecoveryConfig)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("scenarioId")
    @classmethod
    def validate_scenario_id_format(cls, v: str) -> str:
        if not v.startswith("SCN-"):
            raise ValueError(f"Scenario ID must start with 'SCN-'. Got {v}")
        return v

class AttackScenarioExecutionStatus(BaseModel):
    runId: str = Field(default_factory=lambda: f"run-atk-{uuid.uuid4().hex[:8]}")
    scenarioId: str
    currentState: AttackScenarioStateEnum = AttackScenarioStateEnum.CREATED
    virtualTimeElapsed: float = 0.0
    detectedAt: Optional[str] = None
    recoveredAt: Optional[str] = None
    indicatorsObserved: List[str] = Field(default_factory=list)
    errorReason: Optional[str] = None
    startedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())