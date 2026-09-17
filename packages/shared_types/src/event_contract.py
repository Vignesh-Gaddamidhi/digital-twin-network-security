import uuid
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict

class EventCategoryEnum(str, Enum):
    # Week 24 Live Twin Telemetry & Detections
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

    # Week 25 Automated Response Simulation
    RESPONSE_UPDATE = "RESPONSE_UPDATE"

    # Week 28 Event Streaming Infrastructure Lifecycle
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
    """
    Enterprise Event Envelope for all Digital Twin & SOC streaming messages.
    Supports causal lineage tracking (correlationId / causationId) and schema evolution.
    """
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
        """Converts model to a flat string map for Redis Stream XADD operations."""
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
        """Reconstructs strongly-typed CanonicalEvent from Redis stream payload."""
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
            ts = datetime.fromisoformat(ts_raw)
        else:
            ts = datetime.now(timezone.utc)

        return cls(
            eventId=str(data.get("eventId", str(uuid.uuid4()))),
            eventType=EventCategoryEnum(str(data.get("eventType", "HEARTBEAT"))),
            timestamp=ts,
            source=str(data.get("source", "UNKNOWN")),
            environment=str(data.get("environment", "PRODUCTION")),
            correlationId=str(data.get("correlationId", str(uuid.uuid4()))),
            causationId=str(data.get("causationId")) if data.get("causationId") else None,
            deviceId=str(data.get("deviceId")) if data.get("deviceId") else None,
            severity=EventSeverityEnum(str(data.get("severity", "INFO"))),
            schemaVersion=str(data.get("schemaVersion", "1.0")),
            sequence=int(data.get("sequence", 1)),
            payload=payload
        )