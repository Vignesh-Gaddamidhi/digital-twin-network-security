import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timezone
from fastapi import WebSocket, WebSocketDisconnect

from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeConnectionState, DataFreshnessState, BackendHealthState,
    RealtimeEventEnvelope, TwinStateSnapshot, HeartbeatPayload, ErrorPayload
)
from frontend.realtime.realtime_event_manager import realtime_event_manager

logger = logging.getLogger("twin.websocket")

class WebSocketConnectionManager:
    """Enterprise connection manager for multiplexed real-time WebSocket streaming."""

    def __init__(self, heartbeat_interval_seconds: float = 2.0):
        self.active_connections: Set[WebSocket] = set()
        self.heartbeat_interval = heartbeat_interval_seconds
        self._heartbeat_task: Optional[asyncio.Task] = None
        self.processed_event_cache: Set[str] = set()
        self.max_cache_size = 2000

    async def connect(self, websocket: WebSocket) -> TwinStateSnapshot:
        """Accepts WebSocket connection, registers client, and sends initial full snapshot."""
        await websocket.accept()
        self.active_connections.add(websocket)
        realtime_event_manager.connection_state = RealtimeConnectionState.CONNECTED
        realtime_event_manager.backend_health = BackendHealthState.HEALTHY

        # Start heartbeat loop if not active
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        # Immediately build and return complete snapshot for initial state synchronization
        snapshot = realtime_event_manager.generate_full_twin_snapshot()
        await websocket.send_json({
            "type": "SNAPSHOT",
            "snapshot": snapshot.model_dump()
        })
        return snapshot

    def disconnect(self, websocket: WebSocket):
        """Unregisters disconnected client, updates connection state, and cancels heartbeat daemon if idle."""
        self.active_connections.discard(websocket)
        if not self.active_connections:
            realtime_event_manager.connection_state = RealtimeConnectionState.DISCONNECTED
            if self._heartbeat_task and not self._heartbeat_task.done():
                self._heartbeat_task.cancel()

    async def broadcast_envelope(self, envelope: RealtimeEventEnvelope) -> int:
        """Broadcasts an incremental delta event envelope to all connected clients."""
        if not self.active_connections:
            return 0

        # Idempotency cache check
        cache_key = f"{envelope.eventId}:{envelope.sequenceNumber}"
        if cache_key in self.processed_event_cache:
            return 0  # Deduplicated

        self.processed_event_cache.add(cache_key)
        if len(self.processed_event_cache) > self.max_cache_size:
            self.processed_event_cache.pop()

        dead_connections: List[WebSocket] = []
        payload_data = {
            "type": "EVENT",
            "envelope": envelope.model_dump()
        }

        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload_data)
            except (WebSocketDisconnect, RuntimeError, Exception):
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

        return len(self.active_connections)

    async def send_to_client(self, websocket: WebSocket, envelope: RealtimeEventEnvelope):
        """Dispatches an incremental event directly to a single client socket."""
        try:
            await websocket.send_json({
                "type": "EVENT",
                "envelope": envelope.model_dump()
            })
        except Exception:
            self.disconnect(websocket)

    async def broadcast_error(self, error_code: str, message: str, subsystem: str = "GATEWAY", recoverable: bool = True):
        """Broadcasts a sanitized error event without exposing internal stack traces."""
        error_payload = ErrorPayload(
            errorCode=error_code,
            errorMessage=message,
            subsystem=subsystem,
            recoverable=recoverable
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.ERROR,
            payload=error_payload.model_dump()
        )
        await self.broadcast_envelope(env)

    async def trigger_heartbeat(self) -> RealtimeEventEnvelope:
        """Generates and broadcasts a real-time server heartbeat pulse."""
        hb = HeartbeatPayload(
            activeConnectionsCount=len(self.active_connections),
            totalEventsEmitted=realtime_event_manager.current_sequence,
            serverTimeUtc=datetime.now(timezone.utc).isoformat()
        )
        env = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.HEARTBEAT,
            payload=hb.model_dump()
        )
        await self.broadcast_envelope(env)
        return env

    async def _heartbeat_loop(self):
        """Internal daemon loop pulsing periodic heartbeats to maintain socket freshness."""
        try:
            while self.active_connections:
                await asyncio.sleep(self.heartbeat_interval)
                if self.active_connections:
                    await self.trigger_heartbeat()
        except asyncio.CancelledError:
            pass

    def connection_count(self) -> int:
        return len(self.active_connections)

    def connection_status(self) -> Dict[str, Any]:
        freshness, age_sec = realtime_event_manager.compute_freshness_state()
        return {
            "activeClients": len(self.active_connections),
            "connectionState": realtime_event_manager.connection_state.value,
            "backendHealth": realtime_event_manager.backend_health.value,
            "dataFreshness": freshness.value,
            "dataAgeSeconds": age_sec,
            "currentSequence": realtime_event_manager.current_sequence
        }

websocket_connection_manager = WebSocketConnectionManager()