from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class FirewallActionEnum(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DROP = "DROP"

class NetworkZoneTypeEnum(str, Enum):
    INTERNET = "INTERNET"
    EXTERNAL = "EXTERNAL"
    DMZ = "DMZ"
    INTERNAL = "INTERNAL"
    MANAGEMENT = "MANAGEMENT"
    DATABASE = "DATABASE"
    UNKNOWN = "UNKNOWN"

class FirewallRuleModel(BaseModel):
    id: str = Field(default_factory=lambda: f"rule-{uuid.uuid4().hex[:6]}")
    sourceZone: NetworkZoneTypeEnum
    destinationZone: NetworkZoneTypeEnum
    protocol: str = Field(default="TCP")
    destinationPort: Optional[int] = Field(default=None, ge=1, le=65535)
    action: FirewallActionEnum = Field(default=FirewallActionEnum.ALLOW)
    priority: int = Field(default=100, ge=1, le=1000)
    description: str = Field(default="Traffic policy rule")
    status: str = Field(default="ACTIVE")

class NetworkZoneModel(BaseModel):
    id: str = Field(..., min_length=2, description="Unique zone identifier (e.g., zone-dmz)")
    name: NetworkZoneTypeEnum
    trustLevel: int = Field(..., ge=0, le=10, description="0 (Untrusted) to 10 (Maximum Trust)")
    devices: List[str] = Field(default_factory=list, description="IDs of devices assigned to zone")
    subnets: List[str] = Field(default_factory=list)

class TrafficInspectionResult(BaseModel):
    source_device_id: str
    destination_device_id: str
    source_zone: NetworkZoneTypeEnum
    destination_zone: NetworkZoneTypeEnum
    protocol: str
    destination_port: Optional[int]
    decision: FirewallActionEnum
    matched_rule_id: Optional[str] = None
    explanation: str