from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class ZoneDefinitionModel(BaseModel):
    id: str = Field(..., min_length=2, description="Unique zone identifier (e.g., zone-dmz)")
    name: str = Field(..., min_length=2, description="Display name: INTERNET, DMZ, INTERNAL, etc.")
    trust_level: int = Field(default=1, ge=0, le=10, description="0 (Untrusted) to 10 (Restricted)")
    devices: List[str] = Field(default_factory=list, description="IDs of devices assigned to this zone")
    description: str = Field(default="", description="Operational purpose of the zone")
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ZoneBoundaryLinkModel(BaseModel):
    connection_id: str
    source_device: str
    destination_device: str
    source_zone: str
    destination_zone: str
    is_inter_zone: bool
    protocol: str
    port: Optional[int] = None

class ZoneSegmentationGraphModel(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    zone_count: int
    zones: List[ZoneDefinitionModel]
    inter_zone_links: List[ZoneBoundaryLinkModel]
    zone_adjacency: Dict[str, List[str]]