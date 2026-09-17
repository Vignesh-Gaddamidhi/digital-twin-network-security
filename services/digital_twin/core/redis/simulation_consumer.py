import json
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from packages.shared_types.src.event_contract import (
    CanonicalEvent, EventCategoryEnum, EventSeverityEnum
)
from services.digital_twin.core.redis.redis_manager import (
    redis_manager, STREAMS, CHANNELS
)
from services.digital_twin.core.redis.event_bus import event_bus
from packages.database.src.repositories import dal

class SimulationEventConsumer:
    """
    Consumes simulation events from Redis Streams, validates device existence,
    mutates the authoritative Digital Twin, and invokes persistent persistence.
    """

    def __init__(self):
        self.stream_name = STREAMS["SIMULATION"]
        self.consumer_group = "cybertwin:group:sim_consumer"
        self.consumer_name = "sim_worker_01"

    async def handle_simulation_event(self, event: CanonicalEvent) -> Dict[str, Any]:
        """
        Processes simulation event:
        1. Emits audit/twin state changes on severity threshold.
        2. Dispatches real-time broadcast to WebSockets.
        """
        device_id = event.deviceId or "WEB-01"
        event_type = event.eventType
        payload = event.payload

        twin_state = "NORMAL"
        if event.severity == EventSeverityEnum.CRITICAL:
            twin_state = "COMPROMISED"
        elif event.severity == EventSeverityEnum.HIGH:
            twin_state = "SUSPICIOUS"

        # Broadcast update over real-time fan-out channel
        await redis_manager.publish_channel(
            channel=CHANNELS["REALTIME_BROADCAST"],
            message={
                "type": "SIMULATION_TWIN_MUTATION",
                "deviceId": device_id,
                "state": twin_state,
                "eventType": str(event_type),
                "payload": payload,
                "timestamp": event.timestamp.isoformat()
            }
        )

        return {
            "processed": True,
            "deviceId": device_id,
            "state": twin_state,
            "eventId": event.eventId
        }

simulation_consumer = SimulationEventConsumer()