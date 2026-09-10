from typing import Dict, List, Optional
from datetime import datetime, timezone

from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, SecurityCorrelationContext, EventSourceEnum,
    SecurityEventTypeEnum, NormalizedSecuritySeverityEnum
)

SEVERITY_ORDER = {
    NormalizedSecuritySeverityEnum.LOW: 1,
    NormalizedSecuritySeverityEnum.MEDIUM: 2,
    NormalizedSecuritySeverityEnum.HIGH: 3,
    NormalizedSecuritySeverityEnum.CRITICAL: 4
}

class IdsCorrelationEngine:
    """Correlates Suricata alerts and Zeek flow telemetry across 5-tuple within sliding temporal windows."""

    def __init__(self, time_window_seconds: float = 10.0):
        self.time_window_seconds = time_window_seconds
        self.contexts: Dict[str, SecurityCorrelationContext] = {}

    @staticmethod
    def generate_5tuple_key(src_ip: str, dst_ip: str, src_p: Optional[int], dst_p: Optional[int], proto: str) -> str:
        # Standardize bi-directional flow key so forward and reverse match same context
        endpoint_a = f"{src_ip}:{src_p or 0}"
        endpoint_b = f"{dst_ip}:{dst_p or 0}"
        sorted_endpoints = "-".join(sorted([endpoint_a, endpoint_b]))
        return f"{proto.upper()}::{sorted_endpoints}"

    @staticmethod
    def parse_timestamp(ts_str: Optional[str]) -> float:
        if not ts_str:
            return datetime.now(timezone.utc).timestamp()
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
        except Exception:
            return datetime.now(timezone.utc).timestamp()

    def correlate(self, event: NormalizedSecurityEvent) -> SecurityCorrelationContext:
        key = self.generate_5tuple_key(
            event.sourceIP, event.destinationIP, event.sourcePort, event.destinationPort, event.protocol
        )
        evt_epoch = self.parse_timestamp(event.timestamp)
        now_iso = datetime.now(timezone.utc).isoformat()

        context = self.contexts.get(key)

        # Check if existing context exists within time window
        if context:
            ctx_epoch = self.parse_timestamp(context.lastSeen)
            if abs(evt_epoch - ctx_epoch) <= self.time_window_seconds:
                # Update existing context
                context.lastSeen = event.timestamp or now_iso
                context.eventCount += 1
                context.totalBytes += event.bytes
                context.totalPackets += event.packets
                if event.source not in context.sourcesInvolved:
                    context.sourcesInvolved.append(event.source)
                if event.eventId not in context.associatedEventIds:
                    context.associatedEventIds.append(event.eventId)

                if event.eventType == SecurityEventTypeEnum.ALERT:
                    context.hasAlert = True
                    if event.signature not in context.alertSignatures:
                        context.alertSignatures.append(event.signature)

                if SEVERITY_ORDER.get(event.severity, 1) > SEVERITY_ORDER.get(context.highestSeverity, 1):
                    context.highestSeverity = event.severity

                return context

        # Create new context if none exists or previous expired
        new_ctx = SecurityCorrelationContext(
            correlationKey=key,
            firstSeen=event.timestamp or now_iso,
            lastSeen=event.timestamp or now_iso,
            sourceDevice=event.sourceDevice,
            destinationDevice=event.destinationDevice,
            sourceIP=event.sourceIP,
            destinationIP=event.destinationIP,
            sourcePort=event.sourcePort,
            destinationPort=event.destinationPort,
            protocol=event.protocol,
            sourcesInvolved=[event.source],
            eventCount=1,
            totalBytes=event.bytes,
            totalPackets=event.packets,
            hasAlert=(event.eventType == SecurityEventTypeEnum.ALERT),
            highestSeverity=event.severity,
            associatedEventIds=[event.eventId],
            alertSignatures=[event.signature] if event.eventType == SecurityEventTypeEnum.ALERT else []
        )
        self.contexts[key] = new_ctx
        return new_ctx

    def get_context(self, correlation_key: str) -> Optional[SecurityCorrelationContext]:
        return self.contexts.get(correlation_key)

    def list_contexts(self) -> List[SecurityCorrelationContext]:
        return list(self.contexts.values())

    def clear(self):
        self.contexts.clear()

ids_correlation_engine = IdsCorrelationEngine()