from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ServiceCriticalityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ServiceDependencyStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"

class DetailedServiceDependencyModel(BaseModel):
    id: str = Field(default_factory=lambda: f"sdep-{uuid.uuid4().hex[:8]}")
    sourceDevice: str = Field(..., min_length=1, description="Client or consuming device ID")
    sourceService: str = Field(..., min_length=1, description="Consuming application or process")
    destinationDevice: str = Field(..., min_length=1, description="Providing host device ID")
    destinationService: str = Field(..., min_length=1, description="Providing daemon service name")
    protocol: str = Field(default="TCP")
    port: int = Field(..., ge=1, le=65535)
    status: ServiceDependencyStatusEnum = Field(default=ServiceDependencyStatusEnum.ACTIVE)
    criticality: ServiceCriticalityEnum = Field(default=ServiceCriticalityEnum.HIGH)
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ImpactedServiceNode(BaseModel):
    device_id: str
    hostname: str
    service_name: str
    impact_level: str
    dependency_depth: int
    direct_dependency: bool

class ImpactPropagationResult(BaseModel):
    failed_device_id: str
    failed_service: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_impacted_services: int
    total_impacted_devices: int
    blast_radius_score: float
    impacted_services: List[ImpactedServiceNode]
    propagation_chain: List[str]