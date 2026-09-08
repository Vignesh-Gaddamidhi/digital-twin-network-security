from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class PortProbeMetric(BaseModel):
    destinationPort: int
    attemptCount: int = 0
    successfulConnections: int = 0
    failedConnections: int = 0
    portState: str = "CLOSED"

class PortStateMutationConfig(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    newState: str = "OPEN"
    serviceName: str = "alt-http"
    reason: str = "Simulated port state modification"

class PortAnomalyProfile(BaseModel):
    profileId: str = Field(default_factory=lambda: f"portanom-{uuid.uuid4().hex[:6]}")
    name: str = "Unusual-Port-Distribution-Sweep"
    affectedDevice: str = "client-01"
    targetDevice: str = "web-01"
    baselinePorts: List[int] = Field(default_factory=lambda: [80, 443])
    probedPorts: List[int] = Field(
        default_factory=lambda: [21, 22, 25, 53, 80, 110, 443, 8080, 8443]
    )
    portAttemptWeights: Dict[int, int] = Field(
        default_factory=lambda: {
            443: 100,
            80: 40,
            22: 200,
            21: 15,
            25: 15,
            53: 15,
            110: 15,
            8080: 25,
            8443: 20
        }
    )
    mutatePort: Optional[PortStateMutationConfig] = None

class PortAnomalyRunResult(BaseModel):
    runId: str = Field(default_factory=lambda: f"run-portanom-{uuid.uuid4().hex[:8]}")
    profileId: str
    targetDevice: str
    totalAttempts: int
    portMetrics: List[PortProbeMetric] = Field(default_factory=list)
    unusualPortsDetected: List[int] = Field(default_factory=list)
    stateMutated: bool = False
    mutatedPortDetails: Optional[Dict[str, Any]] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())