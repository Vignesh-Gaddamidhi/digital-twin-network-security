from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class DependencyTypeEnum(str, Enum):
    UPSTREAM_CLIENT = "UPSTREAM_CLIENT"
    BACKEND_DATASTORE = "BACKEND_DATASTORE"
    INFRASTRUCTURE_CORE = "INFRASTRUCTURE_CORE"
    INTERNAL_API = "INTERNAL_API"

class ServiceDependencyModel(BaseModel):
    id: str = Field(default_factory=lambda: f"dep-{uuid.uuid4().hex[:8]}")
    source_device_id: str = Field(..., min_length=1, description="Originating client or service node")
    target_device_id: str = Field(..., min_length=1, description="Target service host")
    target_service_name: str = Field(..., min_length=1, description="Service daemon name (e.g., PostgreSQL)")
    target_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="TCP")
    dependency_type: DependencyTypeEnum = Field(default=DependencyTypeEnum.BACKEND_DATASTORE)
    is_critical: bool = Field(default=True)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ServiceDependencyChainResult(BaseModel):
    root_client_id: str
    target_service_id: str
    dependency_chain: List[str]
    total_depth: int
    direct_dependency: bool
    explanation: str