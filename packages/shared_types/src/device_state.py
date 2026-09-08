from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class OperationalStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    MAINTENANCE = "MAINTENANCE"

class SecurityConditionEnum(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    ISOLATED = "ISOLATED"

class VulnerabilityStatusEnum(str, Enum):
    CLEAN = "CLEAN"
    OPEN = "OPEN"
    PATCHING = "PATCHING"
    EXPLOITED = "EXPLOITED"

class PerformanceStateModel(BaseModel):
    cpu: float = Field(default=0.0, description="CPU utilization percentage (0-100%)")
    memory: float = Field(default=0.0, description="Memory utilization percentage (0-100%)")
    networkUtilisation: float = Field(default=0.0, description="Network line saturation percentage (0-100%)")

    @field_validator("cpu")
    @classmethod
    def validate_cpu(cls, v: float) -> float:
        if not (0.0 <= v <= 100.0):
            raise ValueError(f"CPU utilization must be between 0.0 and 100.0%. Got {v}")
        return round(v, 2)

    @field_validator("memory")
    @classmethod
    def validate_memory(cls, v: float) -> float:
        if not (0.0 <= v <= 100.0):
            raise ValueError(f"Memory utilization must be between 0.0 and 100.0%. Got {v}")
        return round(v, 2)

    @field_validator("networkUtilisation")
    @classmethod
    def validate_network(cls, v: float) -> float:
        if not (0.0 <= v <= 100.0):
            raise ValueError(f"Network utilization must be between 0.0 and 100.0%. Got {v}")
        return round(v, 2)

class NetworkTelemetryStateModel(BaseModel):
    activeConnections: int = Field(default=0, ge=0)
    bytesInRate: float = Field(default=0.0, ge=0.0)
    bytesOutRate: float = Field(default=0.0, ge=0.0)

class ServiceRuntimeEntry(BaseModel):
    name: str = Field(..., min_length=1)
    status: str = Field(default="RUNNING") # RUNNING, STOPPED, DEGRADED
    port: int = Field(..., ge=1, le=65535)

class PortStateEntry(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="TCP")
    state: str = Field(default="OPEN") # OPEN, CLOSED, FILTERED
    service: Optional[str] = None

class SecurityStateBlockModel(BaseModel):
    status: SecurityConditionEnum = Field(default=SecurityConditionEnum.NORMAL)
    vulnerabilityStatus: VulnerabilityStatusEnum = Field(default=VulnerabilityStatusEnum.CLEAN)
    activeVulnerabilitiesCount: int = Field(default=0, ge=0)
    compositeRiskScore: float = Field(default=0.0, ge=0.0, le=100.0)

class ComprehensiveDeviceStateModel(BaseModel):
    deviceId: str = Field(..., min_length=1)
    operationalState: OperationalStatusEnum = Field(default=OperationalStatusEnum.ACTIVE)
    performance: PerformanceStateModel = Field(default_factory=PerformanceStateModel)
    network: NetworkTelemetryStateModel = Field(default_factory=NetworkTelemetryStateModel)
    ports: List[PortStateEntry] = Field(default_factory=list)
    services: List[ServiceRuntimeEntry] = Field(default_factory=list)
    security: SecurityStateBlockModel = Field(default_factory=SecurityStateBlockModel)
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class StateTransitionAuditRecord(BaseModel):
    transitionId: str = Field(default_factory=lambda: f"trans-{uuid.uuid4().hex[:8]}")
    deviceId: str
    component: str  # operational, performance, network, ports, services, security
    previousValue: Any
    newValue: Any
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    triggerSource: str = "TELEMETRY"  # TELEMETRY, SIMULATION, OPERATOR
    reason: str = "State update"