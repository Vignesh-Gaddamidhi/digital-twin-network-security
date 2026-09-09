from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class RecoveryStrategyEnum(str, Enum):
    RESTORE_STATE = "RESTORE_STATE"
    STOP_TRAFFIC = "STOP_TRAFFIC"
    CLOSE_SIMULATED_CONNECTIONS = "CLOSE_SIMULATED_CONNECTIONS"
    CLEAR_ALERT = "CLEAR_ALERT"
    RESET_METRICS = "RESET_METRICS"
    RESTORE_BASELINE = "RESTORE_BASELINE"

class ScenarioRecoveryPlan(BaseModel):
    planId: str = Field(default_factory=lambda: f"rec-plan-{uuid.uuid4().hex[:6]}")
    scenarioId: str
    strategy: RecoveryStrategyEnum = RecoveryStrategyEnum.RESTORE_BASELINE
    durationSeconds: float = Field(default=3.0, ge=0.1, le=3600.0)
    affectedDevices: List[str] = Field(default_factory=list)
    stateChangesExpected: Dict[str, Any] = Field(default_factory=dict)
    restoreTraffic: bool = True
    restoreConnections: bool = True
    revertPortMutations: bool = True
    verificationRequired: bool = True

class DeviceRecoveryResult(BaseModel):
    deviceId: str
    connectionsClosed: int = 0
    portsReverted: List[int] = Field(default_factory=list)
    cpuRestored: float = 25.0
    networkUtilisationRestored: float = 20.0
    securityStatusRestored: str = "HEALTHY"
    success: bool = True

class RecoveryExecutionReport(BaseModel):
    reportId: str = Field(default_factory=lambda: f"rec-rep-{uuid.uuid4().hex[:8]}")
    scenarioId: str
    strategyUsed: RecoveryStrategyEnum
    affectedDevices: List[str]
    deviceResults: List[DeviceRecoveryResult] = Field(default_factory=list)
    totalConnectionsClosed: int = 0
    totalPortsReverted: int = 0
    verified: bool = False
    verificationDetails: Dict[str, Any] = Field(default_factory=dict)
    recoveredAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())