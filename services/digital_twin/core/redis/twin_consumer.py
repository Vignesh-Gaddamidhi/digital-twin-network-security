import json
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from packages.shared_types.src.event_contract import (
    CanonicalEvent, EventCategoryEnum, EventSeverityEnum
)
from services.digital_twin.core.redis.redis_manager import (
    redis_manager, STREAMS, CHANNELS
)
from services.digital_twin.core.redis.event_bus import event_bus
from packages.database.src.telemetry_event_repository import telemetry_event_repo

class TwinEventConsumer:
    """
    Consumes high-frequency telemetry from Redis Streams, updates the authoritative
    Digital Twin state engine, maintains ephemeral TTL caches, and writes durable records.
    """

    def __init__(self):
        self.stream_name = STREAMS["TELEMETRY"]
        self.consumer_group = "cybertwin:group:twin_engine"
        self.consumer_name = "twin_worker_01"
        self.snapshot_ttl = 60
        self.is_running = False

    async def process_telemetry_event(self, event: CanonicalEvent) -> Dict[str, Any]:
        device_id = (
            event.deviceId
            or (event.payload.get("device_id") if isinstance(event.payload, dict) else None)
            or (event.payload.get("deviceId") if isinstance(event.payload, dict) else None)
            or "UNKNOWN"
        )
        payload = event.payload if isinstance(event.payload, dict) else {}
        cpu = float(payload.get("cpu_usage", payload.get("cpu", 0.0)))
        memory = float(payload.get("memory_usage", payload.get("memory", 0.0)))
        packet_rate = float(payload.get("packet_rate", 0.0))
        byte_rate = float(payload.get("byte_rate", 0.0))
        active_conns = int(payload.get("active_connections", 0))
        sec_state = str(payload.get("security_state", "NORMAL"))
        risk_score = float(payload.get("risk_score", 0.0))

        twin_mutation = {
            "deviceId": device_id,
            "cpu": cpu,
            "memory": memory,
            "packetRate": packet_rate,
            "byteRate": byte_rate,
            "activeConnections": active_conns,
            "securityState": sec_state,
            "riskScore": risk_score,
            "lastSeen": event.timestamp.isoformat()
        }

        # Ephemeral Snapshot in Redis (TTL: 60s)
        snapshot_key = f"twin:device:{device_id}:latest"
        await redis_manager.set_cache(snapshot_key, twin_mutation, ttl_seconds=self.snapshot_ttl)

        # Async PostgreSQL Persistence
        asyncio.create_task(
            telemetry_event_repo.record_telemetry(
                device_id=device_id,
                cpu_usage=cpu,
                memory_usage=memory,
                packet_rate=packet_rate,
                byte_rate=byte_rate,
                active_connections=active_conns,
                security_state=sec_state,
                risk_score=risk_score,
                source=event.source,
                timestamp=event.timestamp
            )
        )

        # Real-time Pub/Sub broadcast
        await redis_manager.publish_channel(
            channel=CHANNELS["REALTIME_BROADCAST"],
            message={
                "type": "TWIN_TELEMETRY_DELTA",
                "data": twin_mutation
            }
        )

        return twin_mutation

    async def start_consumer_loop(self, batch_size: int = 50, poll_timeout_ms: int = 1000):
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()

        try:
            await redis_manager.client.xgroup_create(
                name=self.stream_name,
                groupname=self.consumer_group,
                id="0",
                mkstream=True
            )
        except Exception:
            pass

        self.is_running = True
        while self.is_running:
            try:
                entries = await redis_manager.client.xreadgroup(
                    groupname=self.consumer_group,
                    consumername=self.consumer_name,
                    streams={self.stream_name: ">"},
                    count=batch_size,
                    block=poll_timeout_ms
                )

                if entries:
                    for s_name, stream_entries in entries:
                        for entry_id, raw_data in stream_entries:
                            event = CanonicalEvent.from_redis_dict(raw_data)
                            if not await event_bus.is_duplicate(event.eventId):
                                await self.process_telemetry_event(event)
                            await redis_manager.client.xack(self.stream_name, self.consumer_group, entry_id)
                else:
                    await asyncio.sleep(0.05)
            except Exception:
                await asyncio.sleep(0.5)

    def stop_consumer_loop(self):
        self.is_running = False

twin_consumer = TwinEventConsumer()