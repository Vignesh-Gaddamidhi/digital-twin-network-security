from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid

class NetworkOperationalState(BaseModel):
    packet_rate_pps: float = 0.0
    byte_rate_bps: float = 0.0
    active_connections_count: int = 0
    latency_ms: float = 0.5
    packet_loss_pct: float = 0.0

class CurrentState(BaseModel):
    status: str = "ONLINE" # ONLINE, DEGRADED, OFFLINE, MAINTENANCE, UNKNOWN
    uptime_seconds: float = 86400.0
    cpu_usage_pct: float = Field(default=15.0, ge=0.0, le=100.0)
    memory_usage_pct: float = Field(default=35.0, ge=0.0, le=100.0)
    network_state: NetworkOperationalState = Field(default_factory=NetworkOperationalState)
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class SecurityStateModel(BaseModel):
    security_status: str = "NORMAL" # NORMAL, MONITORED, SUSPICIOUS, AT_RISK, COMPROMISED, ISOLATED
    risk_score: float = Field(default=10.0, ge=0.0, le=100.0)
    active_alerts: List[str] = Field(default_factory=list)
    vulnerabilities_count: int = 0
    last_security_event: Optional[str] = None
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    last_evaluated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class StateTransitionRecord(BaseModel):
    history_id: str = Field(default_factory=lambda: f"hist-{uuid.uuid4().hex[:8]}")
    device_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    previous_state: str
    new_state: str
    trigger_source: str
    reason: str
    risk_score: float