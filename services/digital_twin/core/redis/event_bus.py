import json
import asyncio
from typing import Callable, Optional, Dict, Any, List
from datetime import datetime, timezone

from packages.shared_types.src.event_contract import (
    CanonicalEvent, EventCategoryEnum, EventSeverityEnum
)
from services.digital_twin.core.redis.redis_manager import (
    redis_manager, STREAMS, CHANNELS
)

class RedisEventBus:
    """Enterprise event bus driving pub/sub and durable stream pipelines."""

    def __init__(self):
        self.dedup_cache_ttl = 300  # 5-minute idempotency window

    async def publish_event(
        self,
        event: CanonicalEvent,
        stream_name: Optional[str] = None,
        broadcast_channel: Optional[str] = None
    ) -> Optional[str]:
        """
        Validates, serializes, appends to durable stream, and publishes to real-time fan-out channel.
        """
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()

        # 1. Route to Stream
        target_stream = stream_name or STREAMS["EVENTS"]
        stream_payload = event.to_redis_dict()
        
        msg_id = await redis_manager.publish_stream_event(
            stream_key=target_stream,
            data=stream_payload,
            max_len=10000
        )

        # 2. Real-time Pub/Sub Fan-out (WebSocket Gateway)
        target_channel = broadcast_channel or CHANNELS["REALTIME_BROADCAST"]
        await redis_manager.publish_channel(
            channel=target_channel,
            message={
                "eventId": event.eventId,
                "eventType": event.eventType,
                "timestamp": event.timestamp.isoformat(),
                "correlationId": event.correlationId,
                "deviceId": event.deviceId,
                "severity": event.severity,
                "payload": event.payload
            }
        )

        return msg_id

    async def is_duplicate(self, event_id: str) -> bool:
        """Enforces idempotent consumer deduplication via atomic Redis keys."""
        if not redis_manager._is_connected or not redis_manager.client:
            return False
        
        dedup_key = f"cybertwin:dedup:{event_id}"
        # setnx with TTL
        is_new = await redis_manager.client.set(dedup_key, "1", ex=self.dedup_cache_ttl, nx=True)
        return is_new is None

    async def subscribe_to_stream(
        self,
        stream_name: str,
        consumer_group: str,
        consumer_name: str,
        handler: Callable[[CanonicalEvent], Any],
        batch_size: int = 10,
        poll_interval: float = 0.1
    ):
        """Durable stream consumer worker with group coordination and error recovery."""
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()

        # Ensure consumer group exists
        try:
            await redis_manager.client.xgroup_create(
                name=stream_name,
                groupname=consumer_group,
                id="0",
                mkstream=True
            )
        except Exception:
            pass  # Group already initialized

        while True:
            try:
                entries = await redis_manager.client.xreadgroup(
                    groupname=consumer_group,
                    consumername=consumer_name,
                    streams={stream_name: ">"},
                    count=batch_size,
                    block=1000
                )

                if entries:
                    for s_name, stream_entries in entries:
                        for entry_id, raw_data in stream_entries:
                            event = CanonicalEvent.from_redis_dict(raw_data)
                            if not await self.is_duplicate(event.eventId):
                                await handler(event)
                            await redis_manager.client.xack(stream_name, consumer_group, entry_id)
                else:
                    await asyncio.sleep(poll_interval)
            except Exception as e:
                await asyncio.sleep(1.0)

event_bus = RedisEventBus()