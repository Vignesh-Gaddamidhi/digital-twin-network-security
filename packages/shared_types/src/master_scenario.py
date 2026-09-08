from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ScenarioStageTypeEnum(str, Enum):
    NORMAL_BASELINE = "NORMAL_BASELINE"
    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    CONNECTION_ANOMALY = "CONNECTION_ANOMALY"
    PORT_ANOMALY = "PORT_ANOMALY"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    REPEATED_CONNECTION = "REPEATED_CONNECTION"
    RECOVERY = "RECOVERY"

class MasterScenarioStageConfig(BaseModel):
    stageId: str = Field(default_factory=lambda: f"stage-{uuid.uuid4().hex[:6]}")
    stageType: ScenarioStageTypeEnum
    durationSeconds: int = Field(default=10, ge=1)
    affectedDevice: str = "client-01"
    targetDevice: str = "web-01"
    targetPort: int = 443
    intensity: float = 1.0
    parameters: Dict[str, Any] = Field(default_factory=dict)

class MasterScenarioDefinition(BaseModel):
    scenarioId: str = Field(default="master-phase7-canonical-001")
    name: str = "Phase 7 Complete Integration Scenario"
    seed: int = 12345
    description: str = "Sequential execution of normal baseline, 5 distinct anomalies, and recovery phases"
    stages: List[MasterScenarioStageConfig] = Field(default_factory=list)

class ScenarioExecutionStatus(BaseModel):
    scenarioId: str
    runId: str
    state: str # CREATED, RUNNING, PAUSED, COMPLETED, STOPPED, FAILED
    currentStageIndex: int
    totalStages: int
    virtualTimeSeconds: float
    totalPacketsEmitted: int
    totalEventsLogged: int
    anomaliesTriggeredCount: int
    startedAt: Optional[str] = None
    lastTickAt: Optional[str] = None