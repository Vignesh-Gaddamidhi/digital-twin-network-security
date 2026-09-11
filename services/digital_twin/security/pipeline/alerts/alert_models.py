from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class AlertStatusEnum(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"

class SecurityAlert(BaseModel):
    alertId: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str
    source: str
    destination: str
    protocol: str
    port: Optional[int] = None
    eventType: str
    severity: str
    detectionSource: str
    detectionType: str
    confidence: float
    riskScore: float
    riskLevel: str
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    affectedDevice: str
    status: AlertStatusEnum = AlertStatusEnum.NEW
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AlertStore:
    """In-memory alert repository with deduplication, lifecycle management, and querying."""

    def __init__(self):
        self._alerts: Dict[str, SecurityAlert] = {}
        self._alert_fingerprints: set = set()

    def add_alert(self, alert: SecurityAlert) -> Tuple_Alert_Added:
        fingerprint = f"{alert.affectedDevice}::{alert.source}::{alert.detectionType}::{alert.port}::{alert.riskLevel}"
        if fingerprint in self._alert_fingerprints:
            # Duplicate alert in same operational window
            return None, True

        self._alert_fingerprints.add(fingerprint)
        self._alerts[alert.alertId] = alert
        return alert, False

    def get_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        return self._alerts.get(alert_id)

    def list_alerts(self, status: Optional[AlertStatusEnum] = None, affected_device: Optional[str] = None) -> List[SecurityAlert]:
        res = list(self._alerts.values())
        if status:
            res = [a for a in res if a.status == status]
        if affected_device:
            res = [a for a in res if a.affectedDevice == affected_device]
        return res

    def update_status(self, alert_id: str, new_status: AlertStatusEnum) -> bool:
        if alert_id in self._alerts:
            self._alerts[alert_id].status = new_status
            return True
        return False

    def clear(self):
        self._alerts.clear()
        self._alert_fingerprints.clear()

Tuple_Alert_Added = Any
alert_store = AlertStore()