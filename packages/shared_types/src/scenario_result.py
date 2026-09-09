from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ScenarioResult(BaseModel):
    scenarioId: str
    runId: str = Field(default_factory=lambda: f"run-res-{uuid.uuid4().hex[:8]}")
    startTime: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    endTime: Optional[str] = None
    durationSeconds: float = 0.0
    eventsGenerated: int = 0
    bytesGenerated: int = 0
    indicatorsObserved: List[str] = Field(default_factory=list)
    alertsGenerated: List[str] = Field(default_factory=list)
    riskScore: float = 0.0
    riskLevel: str = "LOW"
    affectedDevices: List[str] = Field(default_factory=list)
    stateChanges: Dict[str, Any] = Field(default_factory=dict)
    recoveryStatus: str = "PENDING"
    recoveryVerified: bool = False
    finalState: str = "CREATED"
    details: Dict[str, Any] = Field(default_factory=dict)