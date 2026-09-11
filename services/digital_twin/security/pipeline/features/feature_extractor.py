from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import uuid

from services.digital_twin.security.pipeline.normalization.canonical_event import CanonicalEvent
from services.digital_twin.security.pipeline.features.feature_definitions import (
    SecurityFeatureVector, FeatureWindowEnum
)
from services.digital_twin.security.pipeline.features.feature_registry import feature_registry

WINDOW_SECONDS_MAP = {
    FeatureWindowEnum.WINDOW_5S: 5.0,
    FeatureWindowEnum.WINDOW_30S: 30.0,
    FeatureWindowEnum.WINDOW_60S: 60.0
}

class SlidingWindowBuffer:
    """Buffer storing CanonicalEvent items for an entity pair with chronological eviction."""
    def __init__(self, max_retention_seconds: float = 65.0):
        self.max_retention_seconds = max_retention_seconds
        self.events: List[CanonicalEvent] = []

    def add_event(self, event: CanonicalEvent):
        self.events.append(event)
        self.evict(self.events[-1].eventTimestamp)

    def evict(self, current_ts_str: str):
        try:
            curr_epoch = datetime.fromisoformat(current_ts_str.replace("Z", "+00:00")).timestamp()
        except Exception:
            curr_epoch = datetime.now(timezone.utc).timestamp()

        cutoff = curr_epoch - self.max_retention_seconds
        retained = []
        for e in self.events:
            try:
                e_epoch = datetime.fromisoformat(e.eventTimestamp.replace("Z", "+00:00")).timestamp()
                if e_epoch >= cutoff:
                    retained.append(e)
            except Exception:
                retained.append(e)
        self.events = retained

    def get_window_events(self, window_seconds: float, reference_ts_str: str) -> List[CanonicalEvent]:
        try:
            ref_epoch = datetime.fromisoformat(reference_ts_str.replace("Z", "+00:00")).timestamp()
        except Exception:
            ref_epoch = datetime.now(timezone.utc).timestamp()

        start = ref_epoch - window_seconds
        result = []
        for e in self.events:
            try:
                e_epoch = datetime.fromisoformat(e.eventTimestamp.replace("Z", "+00:00")).timestamp()
                if start <= e_epoch <= ref_epoch:
                    result.append(e)
            except Exception:
                result.append(e)
        return result


class FeatureExtractionEngine:
    """Core engine extracting quantitative multi-dimensional feature vectors."""

    def __init__(self):
        self._buffers: Dict[str, SlidingWindowBuffer] = {}
        self.extracted_vectors: List[SecurityFeatureVector] = []

    def _get_buffer(self, src: str, dst: str) -> SlidingWindowBuffer:
        key = f"{src}->{dst}"
        if key not in self._buffers:
            self._buffers[key] = SlidingWindowBuffer()
        return self._buffers[key]

    def ingest_and_extract(
        self,
        event: CanonicalEvent,
        window: FeatureWindowEnum = FeatureWindowEnum.WINDOW_5S
    ) -> SecurityFeatureVector:
        buf = self._get_buffer(event.source, event.destination)
        buf.add_event(event)

        w_sec = WINDOW_SECONDS_MAP.get(window, 5.0)
        events_in_win = buf.get_window_events(w_sec, event.eventTimestamp)

        # 1. Volume
        pkt_count = sum(e.packets for e in events_in_win)
        byte_count = sum(e.bytes for e in events_in_win)
        pkt_rate = round(float(pkt_count) / w_sec, 2)
        byte_rate = round(float(byte_count) / w_sec, 2)

        # 2. Connection
        conn_count = len(events_in_win)
        failed_count = sum(1 for e in events_in_win if e.metadata.get("conn_state") in ("S0", "REJ", "RSTOS0") or e.eventType in ("PORT_ACTIVITY", "AUTH_FAILURE"))
        success_count = max(0, conn_count - failed_count)
        conn_rate = round(float(conn_count) / w_sec, 2)
        failed_ratio = round(float(failed_count) / max(1, conn_count), 4)

        # 3. Port
        ports = [e.port for e in events_in_win if e.port is not None]
        unique_ports = len(set(ports))
        port_attempts = len(ports)
        failed_ports = sum(1 for e in events_in_win if e.port is not None and e.metadata.get("conn_state") == "REJ")

        # 4. Protocol
        protos = [e.protocol.value for e in events_in_win]
        tcp_count = sum(1 for p in protos if p == "TCP")
        udp_count = sum(1 for p in protos if p == "UDP")
        icmp_count = sum(1 for p in protos if p == "ICMP")
        tot_proto = max(1, len(protos))

        # 5. Timing (Inter-arrival and variance)
        timestamps = []
        for e in events_in_win:
            try:
                dt = datetime.fromisoformat(e.eventTimestamp.replace("Z", "+00:00"))
                timestamps.append(dt.timestamp())
            except Exception:
                pass
        timestamps.sort()

        intervals = []
        if len(timestamps) > 1:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        avg_interval = 0.0
        interval_var = 0.0
        inter_arrival = 0.0
        if intervals:
            inter_arrival = intervals[-1]
            avg_interval = sum(intervals) / len(intervals)
            interval_var = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)

        # 6. Direction
        in_bytes = sum(e.bytes for e in events_in_win if e.destination == event.destination and e.metadata.get("direction") == "INBOUND")
        out_bytes = sum(e.bytes for e in events_in_win if e.source == event.source and e.metadata.get("direction") != "INBOUND")
        if in_bytes == 0 and out_bytes == 0:
            out_bytes = byte_count

        in_pkts = sum(e.packets for e in events_in_win if e.metadata.get("direction") == "INBOUND")
        out_pkts = max(1, pkt_count - in_pkts)

        direction_ratio = round(float(out_bytes) / float(in_bytes + 1), 2)

        vector = SecurityFeatureVector(
            vectorId=f"vec-{uuid.uuid4().hex[:8]}",
            targetDevice=event.destination,
            sourceDevice=event.source,
            window=window,
            windowDurationSeconds=w_sec,
            packetCount=pkt_count,
            byteCount=byte_count,
            packetRate=pkt_rate,
            byteRate=byte_rate,
            connectionCount=conn_count,
            failedConnectionCount=failed_count,
            successfulConnectionCount=success_count,
            connectionRate=conn_rate,
            failedConnectionRatio=failed_ratio,
            destinationPort=event.port,
            uniqueDestinationPorts=unique_ports,
            portAttemptCount=port_attempts,
            failedPortAttempts=failed_ports,
            primaryProtocol=event.protocol.value,
            protocolCount=len(protos),
            uniqueProtocols=len(set(protos)),
            protocolRatioTCP=round(tcp_count / tot_proto, 4),
            protocolRatioUDP=round(udp_count / tot_proto, 4),
            protocolRatioICMP=round(icmp_count / tot_proto, 4),
            eventFrequency=conn_rate,
            interArrivalTime=round(inter_arrival, 4),
            averageInterval=round(avg_interval, 4),
            intervalVariance=round(interval_var, 6),
            inboundBytes=in_bytes,
            outboundBytes=out_bytes,
            inboundPackets=in_pkts,
            outboundPackets=out_pkts,
            bytesDirectionRatio=direction_ratio,
            metadata={"last_event_id": event.eventId, "event_type": event.eventType}
        )

        val_errors = feature_registry.validate_vector(vector)
        if val_errors:
            raise ValueError(f"Extracted feature vector failed registry validation: {val_errors}")

        self.extracted_vectors.append(vector)
        return vector

    def extract_multi_window(self, event: CanonicalEvent) -> Dict[str, SecurityFeatureVector]:
        return {
            "5s": self.ingest_and_extract(event, FeatureWindowEnum.WINDOW_5S),
            "30s": self.ingest_and_extract(event, FeatureWindowEnum.WINDOW_30S),
            "60s": self.ingest_and_extract(event, FeatureWindowEnum.WINDOW_60S)
        }

    def clear(self):
        self._buffers.clear()
        self.extracted_vectors.clear()

feature_extraction_engine = FeatureExtractionEngine()