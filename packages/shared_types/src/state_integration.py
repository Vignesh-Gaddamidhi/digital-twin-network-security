from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class StateEventSourceEnum(str, Enum):
    REAL_NETWORK = "REAL_NETWORK"
    SIMULATION = "SIMULATION"

class SupportedMetricEnum(str, Enum):
    CPU = "CPU"
    MEMORY = "MEMORY"
    NETWORK_UTILISATION = "NETWORK_UTILISATION"
    CONNECTIONS = "CONNECTIONS"
    OPEN_PORT = "OPEN_PORT"
    SERVICE_STATUS = "SERVICE_STATUS"
    SECURITY_STATUS = "SECURITY_STATUS"
    VULNERABILITY_STATUS = "VULNERABILITY_STATUS"
    DEVICE_STATE = "DEVICE_STATE"

class UniversalStateEvent(BaseModel):
    eventId: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:8]}")
    source: StateEventSourceEnum = Field(..., description="REAL_NETWORK or SIMULATION")
    deviceId: str = Field(..., min_length=1)
    metric: SupportedMetricEnum = Field(...)
    value: Any = Field(..., description="Metric value (numeric, string, or structured object)")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("Timestamp cannot be empty.")
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            raise ValueError(f"Invalid ISO-8601 timestamp: '{v}'")
        return v

class SourcePartitionStateModel(BaseModel):
    operationalState: Optional[str] = None
    cpu: Optional[float] = None
    memory: Optional[float] = None
    networkUtilisation: Optional[float] = None
    activeConnections: Optional[int] = None
    openPorts: List[int] = Field(default_factory=list)
    services: Dict[str, str] = Field(default_factory=dict) # name -> status
    securityStatus: Optional[str] = None
    vulnerabilities: Dict[str, str] = Field(default_factory=dict) # id -> status
    lastUpdated: Optional[str] = None

class EffectiveTwinStateModel(BaseModel):
    deviceId: str
    operationalState: str = "ACTIVE"
    cpu: float = 0.0
    memory: float = 0.0
    networkUtilisation: float = 0.0
    activeConnections: int = 0
    openPorts: List[int] = Field(default_factory=list)
    services: Dict[str, str] = Field(default_factory=dict)
    securityStatus: str = "NORMAL"
    vulnerabilities: Dict[str, str] = Field(default_factory=dict)
    performanceLevel: str = "NORMAL"
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class DualSourceDeviceState(BaseModel):
    deviceId: str
    real: SourcePartitionStateModel = Field(default_factory=SourcePartitionStateModel)
    simulation: SourcePartitionStateModel = Field(default_factory=SourcePartitionStateModel)
    effective: EffectiveTwinStateModel
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class StateAuditHistoryEntry(BaseModel):
    recordId: str = Field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:8]}")
    deviceId: str
    metric: str
    oldValue: Any
    newValue: Any
    source: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())