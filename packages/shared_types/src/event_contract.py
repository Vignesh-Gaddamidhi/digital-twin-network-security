import uuid
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict

class EventCategoryEnum(str, Enum):
    DEVICE_STATE_UPDATE = "DEVICE_STATE_UPDATE"
    CPU_UPDATE = "CPU_UPDATE"
    MEMORY_UPDATE = "MEMORY_UPDATE"
    TRAFFIC_UPDATE = "TRAFFIC_UPDATE"
    CONNECTION_UPDATE = "CONNECTION_UPDATE"
    THREAT_UPDATE = "THREAT_UPDATE"
    ALERT_UPDATE = "ALERT_UPDATE"
    PREDICTION_UPDATE = "PREDICTION_UPDATE"
    RISK_UPDATE = "RISK_UPDATE"
    ATTACK_PATH_UPDATE = "ATTACK_PATH_UPDATE"
    SIMULATION_STATUS_UPDATE = "SIMULATION_STATUS_UPDATE"
    EARLY_WARNING_UPDATE = "EARLY_WARNING_UPDATE"
    TWIN_STATE_UPDATE = "TWIN_STATE_UPDATE"
    HEARTBEAT = "HEARTBEAT"
    ERROR = "ERROR"
    RESPONSE_UPDATE = "RESPONSE_UPDATE"
    EVENT_PUBLISHED = "EVENT_PUBLISHED"
    EVENT_CONSUMED = "EVENT_CONSUMED"
    EVENT_FAILED = "EVENT_FAILED"

class EventSeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="allow", use_enum_values=True)

    eventId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    eventType: EventCategoryEnum
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(default="TWIN_SIMULATOR")
    environment: str = Field(default="PRODUCTION")
    correlationId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    causationId: Optional[str] = None
    deviceId: Optional[str] = None
    severity: EventSeverityEnum = Field(default=EventSeverityEnum.INFO)
    schemaVersion: str = Field(default="1.0")
    sequence: int = Field(default=1)
    payload: Dict[str, Any] = Field(default_factory=dict)

    def to_redis_dict(self) -> Dict[str, str]:
        import json
        return {
            "eventId": self.eventId,
            "eventType": str(self.eventType),
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "environment": self.environment,
            "correlationId": self.correlationId,
            "causationId": self.causationId or "",
            "deviceId": self.deviceId or "",
            "severity": str(self.severity),
            "schemaVersion": self.schemaVersion,
            "sequence": str(self.sequence),
            "payload": json.dumps(self.payload)
        }

    @classmethod
    def from_redis_dict(cls, data: Dict[str, Any]) -> "CanonicalEvent":
        import json
        payload_raw = data.get("payload", "{}")
        if isinstance(payload_raw, str):
            try:
                payload = json.loads(payload_raw)
            except Exception:
                payload = {"raw": payload_raw}
        else:
            payload = payload_raw or {}

        ts_raw = data.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw)
            except Exception:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        dev_id = data.get("deviceId")
        if not dev_id and isinstance(payload, dict):
            dev_id = payload.get("device_id") or payload.get("deviceId")

        caus_id = data.get("causationId")
        if not caus_id:
            caus_id = None

        return cls(
            eventId=str(data.get("eventId") or str(uuid.uuid4())),
            eventType=EventCategoryEnum(str(data.get("eventType", "HEARTBEAT"))),
            timestamp=ts,
            source=str(data.get("source", "UNKNOWN")),
            environment=str(data.get("environment", "PRODUCTION")),
            correlationId=str(data.get("correlationId") or str(uuid.uuid4())),
            causationId=caus_id,
            deviceId=str(dev_id) if dev_id else None,
            severity=EventSeverityEnum(str(data.get("severity", "INFO"))),
            schemaVersion=str(data.get("schemaVersion", "1.0")),
            sequence=int(data.get("sequence", 1)),
            payload=payload
        )