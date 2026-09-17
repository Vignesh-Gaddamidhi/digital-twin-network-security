import sys
import asyncio
from pathlib import Path
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.core.redis.redis_manager import redis_manager
from services.digital_twin.core.redis.cache_manager import cache_manager, CacheTTLPolicy
from services.digital_twin.core.redis.websocket_distributor import (
    ClientSubscription, DistributedWebSocketGateway
)

class MockWebSocket:
    """Simulates a FastAPI WebSocket client in an automated test harness."""
    def __init__(self):
        self.sent_messages = []
        self.is_open = True

    async def send_json(self, data: dict):
        if not self.is_open:
            raise RuntimeError("Socket closed")
        self.sent_messages.append(data)

async def run_day195_suite():
    print("=" * 80)
    print("       WEEK 28 - DAY 195: WEBSOCKET SCALING & CACHING AUDIT")
    print("================================================================================\n")

    await redis_manager.connect()

    # 1. Cache Storage & TTL Policy Verification
    print("[1/5] Auditing Multi-Tier Cache Storage & Policy Expirations...")
    await cache_manager.set("dashboard", "production", {"globalThreat": 78, "assets": 6}, ttl=CacheTTLPolicy.DASHBOARD_SUMMARY)
    await cache_manager.set("device", "WEB-01", {"cpu": 85.0, "status": "COMPROMISED"}, ttl=CacheTTLPolicy.TELEMETRY_SNAPSHOT)

    dash_val = await cache_manager.get("dashboard", "production")
    dev_val = await cache_manager.get("device", "WEB-01")
    assert dash_val["assets"] == 6
    assert dev_val["status"] == "COMPROMISED"

    ttl_dash = await redis_manager.client.ttl("cybertwin:cache:dashboard:production")
    ttl_dev = await redis_manager.client.ttl("cybertwin:cache:device:WEB-01")
    assert 0 < ttl_dash <= CacheTTLPolicy.DASHBOARD_SUMMARY
    assert 0 < ttl_dev <= CacheTTLPolicy.TELEMETRY_SNAPSHOT
    print(f"    Dashboard KPI TTL : {ttl_dash}s (Limit: {CacheTTLPolicy.DASHBOARD_SUMMARY}s)")
    print(f"    Device Stream TTL : {ttl_dev}s (Limit: {CacheTTLPolicy.TELEMETRY_SNAPSHOT}s)")
    print("    [PASS] Cache storage and TTL rules verified.")

    # 2. Invalidation Event Hooks
    print("\n[2/5] Auditing Selective Cache Invalidation on State Mutations...")
    await cache_manager.on_alert_mutation({"alertId": "ALT-001"})
    invalidated_dash = await cache_manager.get("dashboard", "production")
    assert invalidated_dash is None
    # Device cache should remain unaffected
    retained_dev = await cache_manager.get("device", "WEB-01")
    assert retained_dev is not None
    print("    Dashboard Cache   : Successfully evicted following alert mutation.")
    print("    Device Cache      : Intact (Cross-namespace isolation verified).")
    print("    [PASS] Cache invalidation hooks operational.")

    # 3. WebSocket Handshake & Snapshot Resync
    print("\n[3/5] Auditing Client Registration & State Snapshot Handshake...")
    mock_ws = MockWebSocket()
    gateway = DistributedWebSocketGateway()
    client_sub = await gateway.register_client(mock_ws)

    assert len(mock_ws.sent_messages) == 1
    handshake = mock_ws.sent_messages[0]
    assert handshake["type"] == "SNAPSHOT_RESYNC"
    assert handshake["status"] == "LIVE"
    assert "snapshot" in handshake
    print(f"    Handshake Status  : {handshake['status']}")
    print(f"    Delivered Snapshot: {handshake['snapshot']['kpi']['totalAssets']} Assets Tracked")
    print("    [PASS] Reconnection snapshot delivery verified.")

    # 4. Granular Topic Filtering
    print("\n[4/5] Auditing Topic-Scoped Client Filtering (Selective Fan-Out)...")
    # Set client subscription to only listen for WEB-01
    gateway.update_subscriptions(client_sub, ["DEVICE:WEB-01"])

    # Dispatched message for DB-01 (should be dropped for this client)
    db_msg = {"type": "TWIN_TELEMETRY_DELTA", "deviceId": "DB-01", "cpu": 60.0}
    await gateway.broadcast_to_local_clients(db_msg)
    assert len(mock_ws.sent_messages) == 1  # No new message added

    # Dispatched message for WEB-01 (should be delivered)
    web_msg = {"type": "TWIN_TELEMETRY_DELTA", "deviceId": "WEB-01", "cpu": 92.4}
    await gateway.broadcast_to_local_clients(web_msg)
    assert len(mock_ws.sent_messages) == 2
    assert mock_ws.sent_messages[1]["deviceId"] == "WEB-01"
    print(f"    Message for DB-01 : Filtered out (Bandwidth saved).")
    print(f"    Message for WEB-01: Delivered to client matching subscription filter.")
    print("    [PASS] Topic-scoped routing verified.")

    # 5. Clean up
    print("\n[5/5] Cleaning Up Gateway & Cache Artifacts...")
    gateway.unregister_client(client_sub)
    await cache_manager.invalidate("device", "WEB-01")
    await redis_manager.disconnect()
    print("    [PASS] Client unregistered and cache cleared.")

    print("\n" + "=" * 80)
    print("       ALL DAY 195 WEBSOCKET & CACHING TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day195_suite())