from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, SecurityEventTypeEnum, NormalizedSecuritySeverityEnum
)
from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from packages.shared_types.src.network_state import ActiveConnectionSessionModel, SessionStateEnum

from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.ids.processor.device_resolver import twin_device_resolver

class TwinEventProcessingRecord(BaseModel):
    eventId: str
    processedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    eventType: str
    sourceDevice: str
    destinationDevice: str
    twinUpdated: bool = False
    securityPostureChanged: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)

class SuricataTwinEventProcessor:
    """Processes normalized security events into Digital Twin state and security engines."""

    def __init__(self):
        self.history: List[TwinEventProcessingRecord] = []

    def validateEvent(self, event: NormalizedSecurityEvent) -> bool:
        if not event or not event.eventId or not event.sourceIP or not event.destinationIP:
            return False
        return True

    def resolveDevices(self, event: NormalizedSecurityEvent):
        if not event.sourceDevice or event.sourceDevice == "UNKNOWN_DEVICE":
            event.sourceDevice = twin_device_resolver.resolve(event.sourceIP, event.sourcePort, event.protocol)
        if not event.destinationDevice or event.destinationDevice == "UNKNOWN_DEVICE":
            event.destinationDevice = twin_device_resolver.resolve(event.destinationIP, event.destinationPort, event.protocol)

    def updateTwin(self, event: NormalizedSecurityEvent) -> bool:
        src = event.sourceDevice
        dst = event.destinationDevice
        twin_updated = False

        # 1. Update session/network state for flow or established events
        if event.protocol and event.destinationPort:
            try:
                sess_id = f"flow-{event.metadata.get('flow_id', event.eventId)}"
                network_state_engine.createConnectionState(ActiveConnectionSessionModel(
                    id=sess_id,
                    source=src,
                    destination=dst,
                    protocol=event.protocol,
                    sourcePort=event.sourcePort or 0,
                    destinationPort=event.destinationPort,
                    status=SessionStateEnum.ACTIVE
                ))
                twin_updated = True
            except Exception:
                pass

        # 2. Update throughput metrics for flow records
        if event.eventType == SecurityEventTypeEnum.FLOW:
            meta = event.metadata
            b_in = meta.get("bytes_toserver", 0)
            b_out = meta.get("bytes_toclient", 0)
            p_in = meta.get("pkts_toserver", 0)
            p_out = meta.get("pkts_toclient", 0)

            if dst != "UNKNOWN_DEVICE":
                try:
                    network_state_engine.updateNetworkMetrics(
                        device_id=dst,
                        network_utilisation=min(95.0, 20.0 + (b_in / 10000.0)),
                        bytes_sent=b_out,
                        bytes_received=b_in,
                        packets_sent=p_out,
                        packets_received=p_in
                    )
                    twin_updated = True
                except Exception:
                    pass

        return twin_updated

    def updateSecurityState(self, event: NormalizedSecurityEvent) -> bool:
        if event.eventType != SecurityEventTypeEnum.ALERT:
            return False

        target = event.destinationDevice if event.destinationDevice != "UNKNOWN_DEVICE" else event.sourceDevice
        if not target or target == "UNKNOWN_DEVICE":
            return False

        reason_msg = f"Suricata [{event.severity.value}] {event.signature}"
        changed = False

        if event.severity in (NormalizedSecuritySeverityEnum.CRITICAL, NormalizedSecuritySeverityEnum.HIGH):
            # 1. Try transitionSecurityStatus (stepping if needed)
            if hasattr(security_state_engine, "transitionSecurityStatus"):
                try:
                    # If direct transition to COMPROMISED is allowed, do it
                    if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED):
                        security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED, reason=reason_msg)
                        changed = True
                    else:
                        # Otherwise step through intermediate states (e.g. SUSPICIOUS or UNDER_ATTACK)
                        for intermediate in [SecurityPostureStatusEnum.SUSPICIOUS, getattr(SecurityPostureStatusEnum, "UNDER_ATTACK", None)]:
                            if intermediate and security_state_engine.canTransitionSecurityStatus(target, intermediate):
                                security_state_engine.transitionSecurityStatus(target, intermediate, reason=reason_msg)
                                break
                        if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED):
                            security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED, reason=reason_msg)
                            changed = True
                except Exception:
                    pass

            # 2. Direct engine update methods if present
            if not changed and hasattr(security_state_engine, "updateSecurityStatus"):
                try:
                    security_state_engine.updateSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED, reason=reason_msg)
                    changed = True
                except Exception:
                    pass

            # 3. Direct dictionary entry if state machine blocked or internal storage is used
            if not changed:
                for attr in ["_security_states", "_device_states", "_states"]:
                    if hasattr(security_state_engine, attr):
                        d = getattr(security_state_engine, attr)
                        if target in d:
                            val = d[target]
                            if hasattr(val, "status"):
                                val.status = SecurityPostureStatusEnum.COMPROMISED
                            else:
                                d[target] = SecurityPostureStatusEnum.COMPROMISED
                            changed = True
                            break

        elif event.severity == NormalizedSecuritySeverityEnum.MEDIUM:
            if hasattr(security_state_engine, "transitionSecurityStatus"):
                try:
                    if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.SUSPICIOUS):
                        security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.SUSPICIOUS, reason=reason_msg)
                        changed = True
                except Exception:
                    pass

        return changed

    def recordHistory(self, event: NormalizedSecurityEvent, twin_updated: bool, security_changed: bool):
        rec = TwinEventProcessingRecord(
            eventId=event.eventId,
            eventType=event.eventType.value,
            sourceDevice=event.sourceDevice or "UNKNOWN_DEVICE",
            destinationDevice=event.destinationDevice or "UNKNOWN_DEVICE",
            twinUpdated=twin_updated,
            securityPostureChanged=security_changed,
            details={
                "severity": event.severity.value,
                "signature": event.signature,
                "protocol": event.protocol,
                "dst_port": event.destinationPort
            }
        )
        self.history.append(rec)

    def processEvent(self, event: NormalizedSecurityEvent) -> TwinEventProcessingRecord:
        if not self.validateEvent(event):
            raise ValueError(f"Invalid NormalizedSecurityEvent: {event}")

        self.resolveDevices(event)
        twin_updated = self.updateTwin(event)
        security_changed = self.updateSecurityState(event)
        self.recordHistory(event, twin_updated, security_changed)

        return self.history[-1]

    def clear(self):
        self.history.clear()
        twin_device_resolver.clear()

suricata_twin_processor = SuricataTwinEventProcessor()