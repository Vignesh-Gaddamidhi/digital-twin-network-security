from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class PathHopDetail(BaseModel):
    hop_number: int
    device_id: str
    hostname: str
    device_type: str
    zone: str
    state: str
    egress_connection_id: Optional[str] = None
    firewall_decision: Optional[str] = None

class ReachabilityEvaluationResult(BaseModel):
    source_device: str
    destination_device: str
    is_reachable: bool
    protocol: str
    destination_port: Optional[int] = None
    hop_count: int
    path: List[str]
    hops_detail: List[PathHopDetail]
    total_latency_ms: float
    blocking_reason: Optional[str] = None
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())