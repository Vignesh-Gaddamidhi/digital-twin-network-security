import json
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from services.digital_twin.core.redis.redis_manager import redis_manager

CACHE_PREFIX = "cybertwin:cache:"

class CacheTTLPolicy:
    TELEMETRY_SNAPSHOT = 10      # 10s: Sub-second high-rate device streams
    DASHBOARD_SUMMARY = 15       # 15s: Executive KPI card metrics
    RISK_SUMMARY = 20            # 20s: Threat matrix & dial composite
    ALERTS_RECENT = 30           # 30s: Triage ledger summaries
    INCIDENTS_OPEN = 30          # 30s: Active Kanban cases
    TOPOLOGY_SNAPSHOT = 300      # 5m: Network node/edge logical maps
    ML_METADATA = 600            # 10m: Benchmark leaderboard & confusion heatmaps

class RedisCacheManager:
    """Manages invalidation-aware TTL caching across all SOC UI domains."""

    @staticmethod
    def _make_key(namespace: str, identifier: str = "default") -> str:
        return f"{CACHE_PREFIX}{namespace}:{identifier}"

    # ==================== CACHE READ / WRITE ====================
    async def get(self, namespace: str, identifier: str = "default") -> Optional[Any]:
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()
        key = self._make_key(namespace, identifier)
        return await redis_manager.get_cache(key)

    async def set(self, namespace: str, identifier: str, data: Any, ttl: int):
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()
        key = self._make_key(namespace, identifier)
        await redis_manager.set_cache(key, data, ttl_seconds=ttl)

    # ==================== CACHE INVALIDATION HOOKS ====================
    async def invalidate(self, namespace: str, identifier: Optional[str] = None):
        """Invalidates a single key or an entire namespace pattern."""
        if not redis_manager._is_connected or not redis_manager.client:
            await redis_manager.connect()
        
        if identifier:
            key = self._make_key(namespace, identifier)
            await redis_manager.client.delete(key)
        else:
            pattern = f"{CACHE_PREFIX}{namespace}:*"
            cursor = 0
            while True:
                cursor, keys = await redis_manager.client.scan(cursor=cursor, match=pattern, count=100)
                if keys:
                    await redis_manager.client.delete(*keys)
                if cursor == 0:
                    break

    # ==================== DOMAIN-SPECIFIC ACCESSORS ====================
    async def get_or_set_dashboard_kpi(self, compute_fallback_coro) -> Dict[str, Any]:
        cached = await self.get("dashboard", "production")
        if cached:
            return cached
        computed = await compute_fallback_coro()
        await self.set("dashboard", "production", computed, ttl=CacheTTLPolicy.DASHBOARD_SUMMARY)
        return computed

    async def get_or_set_device_snapshot(self, device_id: str, compute_fallback_coro) -> Dict[str, Any]:
        cached = await self.get("device", device_id)
        if cached:
            return cached
        computed = await compute_fallback_coro()
        await self.set("device", device_id, computed, ttl=CacheTTLPolicy.TELEMETRY_SNAPSHOT)
        return computed

    async def on_alert_mutation(self, alert_payload: Dict[str, Any]):
        """Event hook: Clears stale alert and incident caches upon new detections."""
        await self.invalidate("alerts")
        await self.invalidate("dashboard")

    async def on_risk_mutation(self, device_id: str):
        """Event hook: Clears stale risk metrics upon model recalculations."""
        await self.invalidate("risk", device_id)
        await self.invalidate("dashboard")

cache_manager = RedisCacheManager()