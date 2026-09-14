from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class StateSourceEnum(str, Enum):
    CONFIRMED_SIMULATION_STATE = "CONFIRMED_SIMULATION_STATE"
    ML_PREDICTED_STATE = "ML_PREDICTED_STATE"

class TargetTypeEnum(str, Enum):
    DEVICE = "DEVICE"
    SERVICE = "SERVICE"
    DATABASE = "DATABASE"
    ASSET = "ASSET"
    ZONE = "ZONE"

class EntryPointScore(BaseModel):
    deviceId: str
    exposure: float        # 1.0 if Internet-facing/DMZ, 0.4 if internal
    reachability: float    # 1.0 if reachable from attacker node
    vulnerability: float   # 1.0 if unpatched, 0.4 if patched, 0.2 if none
    assetRisk: float       # normalized Phase 16 risk score in [0.0, 1.0]
    threatProbability: float # Phase 13 threat probability in [0.0, 1.0]
    compositeScore: float  # Weighted aggregation in [0.0, 1.0]
    rationale: str

class AttackTargetDefinition(BaseModel):
    targetId: str = Field(default_factory=lambda: f"TGT-{uuid.uuid4().hex[:6].upper()}")
    deviceId: str
    targetType: TargetTypeEnum = TargetTypeEnum.DEVICE
    assetCriticality: str = "CRITICAL"
    serviceName: Optional[str] = None
    port: Optional[int] = None
    targetZone: str = "DATABASE"
    description: str = ""

class DeviceCompromiseState(BaseModel):
    deviceId: str
    confirmedState: str = "NORMAL"         # NORMAL, COMPROMISED, ISOLATED
    predictedState: str = "NORMAL"         # NORMAL, SUSPICIOUS, AT_RISK
    stateSource: StateSourceEnum = StateSourceEnum.CONFIRMED_SIMULATION_STATE
    compromiseTimestamp: Optional[str] = None
    scenarioId: Optional[str] = None
    isolationActive: bool = False