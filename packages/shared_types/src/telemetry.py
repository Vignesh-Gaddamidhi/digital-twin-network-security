from pydantic import BaseModel, Field, field_validator
from typing import Optional, Any
from datetime import datetime, timezone
import uuid

class TelemetryMetricEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"tel-{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    device_id: str = Field(..., min_length=1, description="Target digital twin device ID")
    metric: str = Field(..., description="Observed metric: packet_rate, cpu_usage, byte_rate, etc.")
    value: float = Field(..., description="Observed numerical value")
    source: str = Field(default="PROBE_SENSOR_ETH0")

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            raise ValueError("Timestamp must be valid ISO-8601 format.")
        return v

    @field_validator("metric")
    @classmethod
    def validate_metric(cls, v: str) -> str:
        allowed = {"packet_rate", "byte_rate", "cpu_usage", "memory_usage", "active_connections", "latency"}
        if v not in allowed:
            raise ValueError(f"Metric '{v}' not supported. Allowed metrics: {allowed}")
        return v