import hashlib
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, SecurityCorrelationContext, SecurityEventTypeEnum,
    NormalizedSecuritySeverityEnum, EventSourceEnum
)
from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from packages.shared_types.src.network_state import ActiveConnectionSessionModel, SessionStateEnum

from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.ids.processor.device_resolver import twin_device_resolver
from services.digital_twin.ids.processor.correlation_engine import ids_correlation_engine

class MultiSourceProcessingSummary(BaseModel):
    eventId: str
    source: str
    eventType: str
    sourceDevice: str
    destinationDevice: str
    correlationKey: str
    sourcesCorrelated: List[str] = Field(default_factory=list)
    hasAlertCorrelated: bool = False
    securityStatusTarget: Optional[str] = None
    isDuplicate: bool = False
    originalTimestamp: str
    ingestedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class MultiSourceEventProcessor:
    """Production Multi-Source Event Processor with Deduplication and Timestamp Preservation."""

    def __init__(self):
        self.processed_ledger: List[NormalizedSecurityEvent] = []
        self.summary_history: List[MultiSourceProcessingSummary] = []
        self._seen_fingerprints: Set[str] = set()

    def _generate_fingerprint(self, event: NormalizedSecurityEvent) -> str:
        content = f"{event.source.value}::{event.eventId}::{event.sourceIP}::{event.destinationIP}::{event.sourcePort}::{event.destinationPort}::{event.protocol}::{event.signature}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def process(self, event: NormalizedSecurityEvent) -> MultiSourceProcessingSummary:
        fingerprint = self._generate_fingerprint(event)
        is_dup = fingerprint in self._seen_fingerprints
        now_iso = datetime.now(timezone.utc).isoformat()
        orig_ts = event.timestamp or now_iso

        # 1. Device Resolution
        if not event.sourceDevice or event.sourceDevice == "UNKNOWN_DEVICE":
            event.sourceDevice = twin_device_resolver.resolve(event.sourceIP, event.sourcePort, event.protocol)
        if not event.destinationDevice or event.destinationDevice == "UNKNOWN_DEVICE":
            event.destinationDevice = twin_device_resolver.resolve(event.destinationIP, event.destinationPort, event.protocol)

        # 2. Correlate across 5-tuple
        context = ids_correlation_engine.correlate(event)

        target_status = None

        # 3. Idempotent Ingestion Check
        if not is_dup:
            self._seen_fingerprints.add(fingerprint)
            self.processed_ledger.append(event)
            self._sync_network_state(event, context)
            target_status = self._sync_security_state(event, context)

        summary = MultiSourceProcessingSummary(
            eventId=event.eventId,
            source=event.source.value,
            eventType=event.eventType.value,
            sourceDevice=event.sourceDevice or "UNKNOWN_DEVICE",
            destinationDevice=event.destinationDevice or "UNKNOWN_DEVICE",
            correlationKey=context.correlationKey,
            sourcesCorrelated=[s.value for s in context.sourcesInvolved],
            hasAlertCorrelated=context.hasAlert,
            securityStatusTarget=target_status,
            isDuplicate=is_dup,
            originalTimestamp=orig_ts,
            ingestedAt=now_iso
        )
        self.summary_history.append(summary)
        return summary

    def _sync_network_state(self, event: NormalizedSecurityEvent, context: SecurityCorrelationContext):
        dst = event.destinationDevice
        src = event.sourceDevice

        if event.protocol and event.destinationPort:
            try:
                sess_id = f"sess-{context.correlationId}"
                network_state_engine.createConnectionState(ActiveConnectionSessionModel(
                    id=sess_id,
                    source=src or "UNKNOWN_DEVICE",
                    destination=dst or "UNKNOWN_DEVICE",
                    protocol=event.protocol,
                    sourcePort=event.sourcePort or 0,
                    destinationPort=event.destinationPort,
                    status=SessionStateEnum.ACTIVE
                ))
            except Exception:
                pass

        if dst and dst != "UNKNOWN_DEVICE" and event.bytes > 0:
            try:
                network_state_engine.updateNetworkMetrics(
                    device_id=dst,
                    network_utilisation=min(95.0, 20.0 + (context.totalBytes / 10000.0)),
                    bytes_sent=0,
                    bytes_received=context.totalBytes,
                    packets_sent=0,
                    packets_received=context.totalPackets
                )
            except Exception:
                pass

    def _sync_security_state(self, event: NormalizedSecurityEvent, context: SecurityCorrelationContext) -> Optional[str]:
        target = event.destinationDevice if event.destinationDevice != "UNKNOWN_DEVICE" else event.sourceDevice
        if not target or target == "UNKNOWN_DEVICE":
            return None

        if context.hasAlert:
            reason = f"IDS Alert ({', '.join(s.value for s in context.sourcesInvolved)}): {', '.join(context.alertSignatures)}"

            if context.highestSeverity in (NormalizedSecuritySeverityEnum.CRITICAL, NormalizedSecuritySeverityEnum.HIGH):
                if hasattr(security_state_engine, "transitionSecurityStatus"):
                    try:
                        if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED):
                            security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED, reason=reason)
                        else:
                            for intermediate in [SecurityPostureStatusEnum.SUSPICIOUS, getattr(SecurityPostureStatusEnum, "UNDER_ATTACK", None)]:
                                if intermediate and security_state_engine.canTransitionSecurityStatus(target, intermediate):
                                    security_state_engine.transitionSecurityStatus(target, intermediate, reason=reason)
                                    break
                            if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED):
                                security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.COMPROMISED, reason=reason)
                    except Exception:
                        pass
                return "COMPROMISED"

            elif context.highestSeverity == NormalizedSecuritySeverityEnum.MEDIUM:
                if hasattr(security_state_engine, "transitionSecurityStatus"):
                    try:
                        if security_state_engine.canTransitionSecurityStatus(target, SecurityPostureStatusEnum.SUSPICIOUS):
                            security_state_engine.transitionSecurityStatus(target, SecurityPostureStatusEnum.SUSPICIOUS, reason=reason)
                    except Exception:
                        pass
                return "SUSPICIOUS"

        return None

    def get_chronological_history(self) -> List[MultiSourceProcessingSummary]:
        def _parse(t: str) -> float:
            try:
                return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()
            except Exception:
                return 0.0
        return sorted(self.summary_history, key=lambda s: _parse(s.originalTimestamp))

    def clear(self):
        self.processed_ledger.clear()
        self.summary_history.clear()
        self._seen_fingerprints.clear()
        ids_correlation_engine.clear()

multi_source_processor = MultiSourceEventProcessor()