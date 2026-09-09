from typing import List, Dict, Any, Optional
from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, EventSourceEnum, SecurityEventTypeEnum, NormalizedSecuritySeverityEnum
)
from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from services.digital_twin.ids.suricata.parser.eve_parser import suricata_eve_parser
from services.digital_twin.ids.suricata.normalizer.suricata_adapter import suricata_adapter
from services.digital_twin.core.state.security_state_engine import security_state_engine

class IdsTelemetryProcessor:
    """Master telemetry pipeline processor ingesting, normalizing, and applying IDS events."""

    def __init__(self):
        self.processed_events: List[NormalizedSecurityEvent] = []

    def ingest_suricata_eve_json(self, raw_json_str: str) -> List[NormalizedSecurityEvent]:
        records = suricata_eve_parser.parse_records(raw_json_str)
        normalized = []

        for rec in records:
            norm_evt = suricata_adapter.normalize(rec)
            self.processed_events.append(norm_evt)
            normalized.append(norm_evt)

            # Direct state feedback to Digital Twin
            self._apply_event_to_twin(norm_evt)

        return normalized

    def _apply_event_to_twin(self, event: NormalizedSecurityEvent):
        target = event.destinationDevice or event.sourceDevice
        if not target:
            return

        if event.eventType == SecurityEventTypeEnum.ALERT:
            if event.severity in (NormalizedSecuritySeverityEnum.CRITICAL, NormalizedSecuritySeverityEnum.HIGH):
                reason_msg = f"IDS Alert ({event.source.value}): {event.signature}"
                
                # Step through valid state machine transitions (NORMAL -> SUSPICIOUS -> COMPROMISED)
                try:
                    if hasattr(security_state_engine, "canTransitionSecurityStatus"):
                        if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.SUSPICIOUS):
                            security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.SUSPICIOUS, reason=reason_msg)
                        if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED):
                            security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED, reason=reason_msg)
                    
                    # Fallback direct update method
                    security_state_engine.updateSecurityStatus(
                        device_id=target,
                        status=SecurityPostureStatusEnum.COMPROMISED,
                        reason=reason_msg
                    )
                except Exception:
                    try:
                        # Direct state table override if state engine has internal dict
                        if hasattr(security_state_engine, "_states") and target in security_state_engine._states:
                            security_state_engine._states[target].status = SecurityPostureStatusEnum.COMPROMISED
                            security_state_engine._states[target].reason = reason_msg
                    except Exception:
                        pass

    def clear(self):
        self.processed_events.clear()

ids_processor = IdsTelemetryProcessor()