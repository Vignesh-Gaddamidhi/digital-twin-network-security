from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class SecurityPostureStatusEnum(str, Enum):
    NORMAL = "NORMAL"
    MONITORED = "MONITORED"
    SUSPICIOUS = "SUSPICIOUS"
    AT_RISK = "AT_RISK"
    COMPROMISED = "COMPROMISED"
    ISOLATED = "ISOLATED"
    UNKNOWN = "UNKNOWN"

class VulnerabilityLifecycleStatusEnum(str, Enum):
    OPEN = "OPEN"
    MITIGATED = "MITIGATED"
    PATCHED = "PATCHED"
    ACCEPTED = "ACCEPTED"
    UNKNOWN = "UNKNOWN"

class VulnerabilitySeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

class DynamicVulnerabilityEntity(BaseModel):
    id: str = Field(..., min_length=2, description="Vulnerability or CVE identifier (e.g. VULN-001, CVE-2024-21413)")
    name: str = Field(..., min_length=1)
    severity: VulnerabilitySeverityEnum = Field(default=VulnerabilitySeverityEnum.HIGH)
    cvssScore: float = Field(default=7.5, ge=0.0, le=10.0)
    affectedService: str = Field(..., min_length=1)
    affectedVersion: Optional[str] = None
    status: VulnerabilityLifecycleStatusEnum = Field(default=VulnerabilityLifecycleStatusEnum.OPEN)
    discoveredAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lastUpdated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class DeviceVulnerabilitySummary(BaseModel):
    deviceId: str
    totalOpen: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    vulnerabilities: List[DynamicVulnerabilityEntity] = Field(default_factory=list)

class SecurityStateTransitionRecord(BaseModel):
    recordId: str = Field(default_factory=lambda: f"sec-tr-{uuid.uuid4().hex[:8]}")
    deviceId: str
    previousStatus: SecurityPostureStatusEnum
    newStatus: SecurityPostureStatusEnum
    reason: str
    source: str = "ANOMALY_DETECTOR"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class VulnerabilityTransitionRecord(BaseModel):
    recordId: str = Field(default_factory=lambda: f"vuln-tr-{uuid.uuid4().hex[:8]}")
    deviceId: str
    vulnerabilityId: str
    previousStatus: VulnerabilityLifecycleStatusEnum
    newStatus: VulnerabilityLifecycleStatusEnum
    reason: str
    source: str = "PATCH_MANAGER"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())