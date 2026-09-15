from typing import Dict, Any, List, Optional, Set
import math

from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeConnectionState, RealtimeEventEnvelope, TwinStateSnapshot
)

class RealtimeClientSyncEngine:
    """Client-side synchronization state engine managing backoff, deduplication, and resync."""

    def __init__(self, base_delay: float = 1.0, max_delay: float = 10.0, max_retries: int = 5):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.reconnect_attempts = 0
        self.connection_state = RealtimeConnectionState.DISCONNECTED
        self.last_applied_sequence: int = 0
        self.processed_event_ids: Set[str] = set()
        self.client_twin_state: Dict[str, Any] = {}
        self.sequence_gaps_detected: int = 0
        self.duplicates_rejected: int = 0

    def compute_reconnect_backoff_delay(self) -> float:
        """Calculates exponential backoff delay with upper clamping."""
        delay = min(self.max_delay, self.base_delay * (2 ** self.reconnect_attempts))
        self.reconnect_attempts += 1
        return round(delay, 2)

    def reset_reconnect_attempts(self):
        self.reconnect_attempts = 0
        self.connection_state = RealtimeConnectionState.CONNECTED

    def apply_initial_snapshot(self, snapshot: TwinStateSnapshot):
        """Initializes client-side state directly from full baseline snapshot."""
        self.client_twin_state = snapshot.model_dump()
        self.last_applied_sequence = snapshot.sequenceNumber
        self.connection_state = RealtimeConnectionState.CONNECTED
        self.reset_reconnect_attempts()

    def apply_incremental_envelope(self, envelope: RealtimeEventEnvelope) -> bool:
        """Applies incremental delta event with duplicate and ordering checks."""
        # 1. Duplicate event check
        if envelope.eventId in self.processed_event_ids or envelope.sequenceNumber <= self.last_applied_sequence:
            self.duplicates_rejected += 1
            return False

        # 2. Sequence gap detection
        if self.last_applied_sequence > 0 and envelope.sequenceNumber > (self.last_applied_sequence + 1):
            self.sequence_gaps_detected += 1

        # 3. Apply state mutation
        self.processed_event_ids.add(envelope.eventId)
        self.last_applied_sequence = envelope.sequenceNumber

        # Simple state merge
        if envelope.eventType == RealtimeEventType.DEVICE_STATE_UPDATE:
            did = envelope.payload.get("deviceId")
            new_st = envelope.payload.get("newState")
            if "devices" in self.client_twin_state:
                for d in self.client_twin_state["devices"]:
                    if d.get("deviceId") == did:
                        d["securityState"] = new_st

        return True

    def handle_reconnect_resync(self, fresh_snapshot: TwinStateSnapshot) -> int:
        """Resets sequence tracking and re-aligns baseline state after a disconnect gap."""
        old_seq = self.last_applied_sequence
        self.apply_initial_snapshot(fresh_snapshot)
        return fresh_snapshot.sequenceNumber - old_seq

realtime_client_sync = RealtimeClientSyncEngine()