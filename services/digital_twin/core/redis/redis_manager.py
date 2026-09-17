import os
import json
import asyncio
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError, TimeoutError, AuthenticationError

class RedisHealthStatus:
    HEALTHY = "REDIS_HEALTHY"
    UNAVAILABLE = "REDIS_UNAVAILABLE"
    TIMEOUT = "REDIS_TIMEOUT"
    AUTH_ERROR = "REDIS_AUTH_ERROR"
    CONNECTION_ERROR = "REDIS_CONNECTION_ERROR"

# Canonical Stream and Channel Namespaces
STREAMS = {
    "TELEMETRY": "cybertwin:stream:telemetry",
    "EVENTS": "cybertwin:stream:events",
    "SIMULATION": "cybertwin:stream:simulation",
    "ALERTS": "cybertwin:stream:alerts",
    "TWIN_MUTATIONS": "cybertwin:stream:twin_mutations",
    "ML_INFERENCE": "cybertwin:stream:ml_inference"
}

CHANNELS = {
    "REALTIME_BROADCAST": "cybertwin:channel:realtime",
    "INCIDENTS_NOTIFY": "cybertwin:channel:incidents",
    "SYSTEM_NOTIFY": "cybertwin:channel:system"
}

class RedisServiceManager:
    """Manages Redis connection lifecycle, Streams, Pub/Sub, and Cache operations."""

    def __init__(self):
        self.host = os.getenv("REDIS_HOST", "127.0.0.1")
        self.port = int(os.getenv("REDIS_PORT", 6379))
        self.db = int(os.getenv("REDIS_DB", 0))
        self.password = os.getenv("REDIS_PASSWORD", None) or None
        self.timeout = float(os.getenv("REDIS_TIMEOUT_SECONDS", 2.0))
        self.pool: Optional[aioredis.ConnectionPool] = None
        self.client: Optional[aioredis.Redis] = None
        self._is_connected = False

    async def connect(self) -> bool:
        """Initializes connection pool with health validation."""
        try:
            self.pool = aioredis.ConnectionPool(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
                decode_responses=True,
                max_connections=20
            )
            self.client = aioredis.Redis(connection_pool=self.pool)
            await asyncio.wait_for(self.client.ping(), timeout=self.timeout)
            self._is_connected = True
            return True
        except Exception:
            self._is_connected = False
            return False

    async def disconnect(self):
        """Cleanly releases connection pool resources."""
        if self.client:
            await self.client.aclose()
        if self.pool:
            await self.pool.disconnect()
        self._is_connected = False

    async def check_health(self) -> Tuple[str, Optional[str]]:
        """Returns (Status, Diagnostic Message) derived from actual ping response."""
        if not self.client:
            return RedisHealthStatus.UNAVAILABLE, "Redis client not initialized"
        try:
            pong = await asyncio.wait_for(self.client.ping(), timeout=self.timeout)
            if pong:
                return RedisHealthStatus.HEALTHY, None
            return RedisHealthStatus.UNAVAILABLE, "Ping did not return PONG"
        except TimeoutError:
            return RedisHealthStatus.TIMEOUT, f"Operation timed out after {self.timeout}s"
        except AuthenticationError:
            return RedisHealthStatus.AUTH_ERROR, "Invalid Redis credentials"
        except ConnectionError as ce:
            return RedisHealthStatus.CONNECTION_ERROR, str(ce)
        except Exception as e:
            return RedisHealthStatus.UNAVAILABLE, str(e)

    # ==================== STREAM OPERATIONS ====================
    async def publish_stream_event(
        self,
        stream_key: str,
        data: Dict[str, Any],
        max_len: int = 10000
    ) -> Optional[str]:
        """Appends an event payload to a Redis Stream with automated ring-buffer trimming."""
        if not self._is_connected or not self.client:
            return None
        payload = {k: json.dumps(v) if isinstance(v, (dict, list, bool)) else str(v) for k, v in data.items()}
        payload["_timestamp"] = datetime.now(timezone.utc).isoformat()
        return await self.client.xadd(name=stream_key, fields=payload, maxlen=max_len, approximate=True)

    async def read_stream_events(
        self,
        stream_key: str,
        last_id: str = "0",
        count: int = 50
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """Reads batch events from a stream starting after last_id."""
        if not self._is_connected or not self.client:
            return []
        res = await self.client.xread(streams={stream_key: last_id}, count=count)
        if not res:
            return []
        parsed = []
        for s_name, entries in res:
            for entry_id, raw_fields in entries:
                parsed_fields = {}
                for k, v in raw_fields.items():
                    try:
                        parsed_fields[k] = json.loads(v)
                    except (json.JSONDecodeError, TypeError):
                        parsed_fields[k] = v
                parsed.append((entry_id, parsed_fields))
        return parsed

    # ==================== PUB/SUB OPERATIONS ====================
    async def publish_channel(self, channel: str, message: Dict[str, Any]) -> int:
        """Publishes real-time fan-out message to subscribers (e.g. WebSocket router)."""
        if not self._is_connected or not self.client:
            return 0
        return await self.client.publish(channel, json.dumps(message))

    # ==================== CACHING WITH TTL ====================
    async def set_cache(self, key: str, value: Any, ttl_seconds: int = 60):
        """Sets temporary key with Time-To-Live."""
        if not self._is_connected or not self.client:
            return
        serialized = json.dumps(value) if not isinstance(value, str) else value
        await self.client.set(key, serialized, ex=ttl_seconds)

    async def get_cache(self, key: str) -> Optional[Any]:
        """Fetches temporary key from cache."""
        if not self._is_connected or not self.client:
            return None
        val = await self.client.get(key)
        if val is None:
            return None
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return val

redis_manager = RedisServiceManager()