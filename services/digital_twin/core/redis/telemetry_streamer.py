import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from packages.shared_types.src.event_contract import (
    CanonicalEvent, EventCategoryEnum, EventSeverityEnum
)
from services.digital_twin.core.redis.redis_manager import (
    redis_manager, STREAMS
)
from services.digital_twin.core.redis.event_bus import event_bus

class TelemetryStreamer:
    """Publishes continuous or batched device telemetry frames directly to Redis Streams."""

    @staticmethod
    async def emit_device_telemetry(
        device_id: str,
        cpu_usage: float,
        memory_usage: float,
        packet_rate: float,
        byte_rate: float,
        active_connections: int = 10,
        security_state: str = "NORMAL",
        risk_score: float = 0.0,
        correlation_id: Optional[str] = None
    ) -> Optional[str]:
        event = CanonicalEvent(
            eventType=EventCategoryEnum.CPU_UPDATE,
            source="TELEMETRY_STREAMER",
            deviceId=device_id,
            correlationId=correlation_id or "",
            severity=EventSeverityEnum.CRITICAL if security_state == "COMPROMISED" else EventSeverityEnum.INFO,
            payload={
                "device_id": device_id,
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "packet_rate": packet_rate,
                "byte_rate": byte_rate,
                "active_connections": active_connections,
                "security_state": security_state,
                "risk_score": risk_score
            }
        )

        return await event_bus.publish_event(
            event=event,
            stream_name=STREAMS["TELEMETRY"]
        )

telemetry_streamer = TelemetryStreamer()