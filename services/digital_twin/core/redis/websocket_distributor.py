import json
import asyncio
from typing import Dict, Any, Set, Optional, List
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime, timezone

from services.digital_twin.core.redis.redis_manager import redis_manager, CHANNELS
from services.digital_twin.core.redis.cache_manager import cache_manager, CacheTTLPolicy

class ClientSubscription:
    """Tracks topics and device filters for an active WebSocket client."""
    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.topics: Set[str] = {"ALL"}  # Defaults to ALL; can include "DEVICE:WEB-01", "SIMULATION", "ALERTS"
        self.connected_at = datetime.now(timezone.utc)

    def matches(self, message: Dict[str, Any]) -> bool:
        if "ALL" in self.topics:
            return True
        
        msg_type = message.get("type", "")
        dev_id = message.get("deviceId") or message.get("data", {}).get("deviceId")

        if msg_type in self.topics:
            return True
        if dev_id and f"DEVICE:{dev_id}" in self.topics:
            return True
        if "SIMULATION" in self.topics and "SIMULATION" in msg_type:
            return True
        if "ALERTS" in self.topics and ("ALERT" in msg_type or "THREAT" in msg_type):
            return True
        return False

class DistributedWebSocketGateway:
    """
    Subscribes to Redis Pub/Sub channels and multiplexes incoming
    events out to locally connected WebSocket clients according to their subscriptions.
    """

    def __init__(self):
        self.active_clients: Set[ClientSubscription] = set()
        self.pubsub_task: Optional[asyncio.Task] = None
        self.is_listening = False

    async def register_client(self, websocket: WebSocket) -> ClientSubscription:
        sub = ClientSubscription(websocket)
        self.active_clients.add(sub)
        
        # Ensure the Redis Pub/Sub listener is running
        if not self.is_listening:
            self.start_redis_listener()

        # Send Initial Handshake & Snapshot Resync
        snapshot = await self.build_resync_snapshot()
        await websocket.send_json({
            "type": "SNAPSHOT_RESYNC",
            "status": "LIVE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "snapshot": snapshot
        })
        return sub

    def unregister_client(self, sub: ClientSubscription):
        self.active_clients.discard(sub)

    def update_subscriptions(self, sub: ClientSubscription, topics: List[str]):
        sub.topics = set(topics)

    async def build_resync_snapshot(self) -> Dict[str, Any]:
        """Provides point-in-time state so reconnected clients recover immediately."""
        kpi = await cache_manager.get("dashboard", "production") or {
            "totalAssets": 6,
            "isolatedAssets": 1,
            "globalThreatPct": 78,
            "activeThreats": 4,
            "networkHealthPct": 77.4
        }
        return {"kpi": kpi}

    def start_redis_listener(self):
        if not self.pubsub_task or self.pubsub_task.done():
            self.is_listening = True
            self.pubsub_task = asyncio.create_task(self._redis_subscription_loop())

    async def _redis_subscription_loop(self):
        """Dedicated background task reading messages from Redis Pub/Sub."""
        while self.is_listening:
            try:
                if not redis_manager._is_connected or not redis_manager.client:
                    await redis_manager.connect()

                pubsub = redis_manager.client.pubsub()
                await pubsub.subscribe(CHANNELS["REALTIME_BROADCAST"])

                async for message in pubsub.listen():
                    if message["type"] == "message":
                        try:
                            payload = json.loads(message["data"])
                            await self.broadcast_to_local_clients(payload)
                        except Exception:
                            pass
            except Exception:
                await asyncio.sleep(1.0)

    async def broadcast_to_local_clients(self, message: Dict[str, Any]):
        """Dispatches an incoming Redis event to all matching local clients."""
        dead_clients = []
        for sub in self.active_clients:
            if sub.matches(message):
                try:
                    await sub.websocket.send_json(message)
                except (WebSocketDisconnect, RuntimeError):
                    dead_clients.append(sub)

        for dead in dead_clients:
            self.unregister_client(dead)

ws_gateway = DistributedWebSocketGateway()