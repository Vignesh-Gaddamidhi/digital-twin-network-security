from typing import Dict, Any, Optional
from datetime import datetime, timezone

from services.digital_twin.security.pipeline.events.network_event import (
    NetworkEvent, NetworkEventTypeEnum, DetectionSourceEnum, EventSeverityEnum,
    event_id_generator
)
from services.digital_twin.security.pipeline.events.network_event_validator import network_event_validator
from services.digital_twin.ids.processor.device_resolver import twin_device_resolver

class NetworkEventFactory:
    """Factory converting diverse raw telemetry into canonical NetworkEvent instances."""

    @staticmethod
    def _parse_ts(raw_ts: Any) -> str:
        if not raw_ts:
            return datetime.now(timezone.utc).isoformat()
        if isinstance(raw_ts, (int, float)):
            try:
                return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc).isoformat()
            except Exception:
                pass
        return str(raw_ts)

    @classmethod
    def from_packet(cls, pkt: Dict[str, Any]) -> NetworkEvent:
        src_ip = pkt.get("sourceIP") or pkt.get("src_ip", "0.0.0.0")
        dst_ip = pkt.get("destinationIP") or pkt.get("dest_ip", "0.0.0.0")
        src_p = pkt.get("sourcePort") or pkt.get("src_port")
        dst_p = pkt.get("destinationPort") or pkt.get("dest_port")
        proto = str(pkt.get("protocol", "TCP")).upper()

        src_dev = pkt.get("sourceDevice") or twin_device_resolver.resolve(src_ip, src_p, proto)
        dst_dev = pkt.get("destinationDevice") or twin_device_resolver.resolve(dst_ip, dst_p, proto)

        event_type = NetworkEventTypeEnum.NETWORK_CONNECTION
        if dst_p == 53 or proto == "UDP" and (dst_p == 53 or src_p == 53):
            event_type = NetworkEventTypeEnum.DNS_QUERY
        elif dst_p == 80:
            event_type = NetworkEventTypeEnum.HTTP_REQUEST
        elif dst_p == 443:
            event_type = NetworkEventTypeEnum.HTTPS_CONNECTION
        elif dst_p == 22:
            event_type = NetworkEventTypeEnum.SSH_CONNECTION

        event = NetworkEvent(
            eventId=event_id_generator.generate(),
            timestamp=cls._parse_ts(pkt.get("timestamp")),
            source=src_dev,
            destination=dst_dev,
            sourcePort=src_p,
            destinationPort=dst_p,
            protocol=proto,
            eventType=event_type,
            severity=EventSeverityEnum.INFO,
            detectionSource=DetectionSourceEnum.PACKET_CAPTURE,
            bytes=int(pkt.get("bytes") or 0),
            packets=int(pkt.get("packets") or 1),
            metadata={"raw_type": "packet", **pkt.get("details", {})}
        )
        network_event_validator.assert_valid(event)
        return event

    @classmethod
    def from_suricata(cls, eve: Dict[str, Any]) -> NetworkEvent:
        src_ip = eve.get("src_ip", "0.0.0.0")
        dst_ip = eve.get("dest_ip", "0.0.0.0")
        src_p = eve.get("src_port")
        dst_p = eve.get("dest_port")
        proto = str(eve.get("proto", "TCP")).upper()

        src_dev = twin_device_resolver.resolve(src_ip, src_p, proto)
        dst_dev = twin_device_resolver.resolve(dst_ip, dst_p, proto)

        raw_type = str(eve.get("event_type", "alert")).lower()
        severity = EventSeverityEnum.INFO
        signature = None

        if raw_type == "alert":
            event_type = NetworkEventTypeEnum.IDS_ALERT
            alert_obj = eve.get("alert", {})
            signature = alert_obj.get("signature", "Suricata Alert")
            raw_sev = alert_obj.get("severity", 3)
            sev_map = {1: EventSeverityEnum.CRITICAL, 2: EventSeverityEnum.HIGH, 3: EventSeverityEnum.MEDIUM, 4: EventSeverityEnum.LOW}
            severity = sev_map.get(raw_sev, EventSeverityEnum.MEDIUM)
        elif raw_type == "dns":
            event_type = NetworkEventTypeEnum.DNS_QUERY
        elif raw_type == "http":
            event_type = NetworkEventTypeEnum.HTTP_REQUEST
        elif raw_type == "tls":
            event_type = NetworkEventTypeEnum.HTTPS_CONNECTION
        elif dst_p == 22 or src_p == 22:
            event_type = NetworkEventTypeEnum.SSH_CONNECTION
        else:
            event_type = NetworkEventTypeEnum.NETWORK_CONNECTION

        flow_block = eve.get("flow", {})
        total_b = int(flow_block.get("bytes_toserver", 0)) + int(flow_block.get("bytes_toclient", 0))
        total_p = int(flow_block.get("pkts_toserver", 0)) + int(flow_block.get("pkts_toclient", 0))

        event = NetworkEvent(
            eventId=event_id_generator.generate(),
            timestamp=cls._parse_ts(eve.get("timestamp")),
            source=src_dev,
            destination=dst_dev,
            sourcePort=src_p,
            destinationPort=dst_p,
            protocol=proto,
            eventType=event_type,
            severity=severity,
            detectionSource=DetectionSourceEnum.SURICATA,
            bytes=total_b,
            packets=max(1, total_p),
            signature=signature,
            metadata={"eve_type": raw_type, "flow_id": eve.get("flow_id")}
        )
        network_event_validator.assert_valid(event)
        return event

    @classmethod
    def from_zeek(cls, log_rec: Dict[str, Any], stream_hint: Optional[str] = None) -> NetworkEvent:
        src_ip = log_rec.get("id.orig_h") or log_rec.get("src_ip", "0.0.0.0")
        dst_ip = log_rec.get("id.resp_h") or log_rec.get("dest_ip", "0.0.0.0")
        src_p = log_rec.get("id.orig_p") or log_rec.get("src_port")
        dst_p = log_rec.get("id.resp_p") or log_rec.get("dest_port")
        proto = str(log_rec.get("proto", "TCP")).upper()

        src_dev = twin_device_resolver.resolve(src_ip, src_p, proto)
        dst_dev = twin_device_resolver.resolve(dst_ip, dst_p, proto)

        log_hint = (stream_hint or "").lower()
        if "query" in log_rec or log_hint == "dns":
            event_type = NetworkEventTypeEnum.DNS_QUERY
        elif "method" in log_rec or log_hint == "http":
            event_type = NetworkEventTypeEnum.HTTP_REQUEST
        elif "server_name" in log_rec or log_hint in ("ssl", "tls") or dst_p == 443:
            event_type = NetworkEventTypeEnum.HTTPS_CONNECTION
        elif "auth_success" in log_rec or log_hint == "ssh" or dst_p == 22:
            event_type = NetworkEventTypeEnum.SSH_CONNECTION
        else:
            event_type = NetworkEventTypeEnum.NETWORK_CONNECTION

        b_orig = int(log_rec.get("orig_bytes") or 0) if log_rec.get("orig_bytes") not in (None, "-") else 0
        b_resp = int(log_rec.get("resp_bytes") or 0) if log_rec.get("resp_bytes") not in (None, "-") else 0

        event = NetworkEvent(
            eventId=event_id_generator.generate(),
            timestamp=cls._parse_ts(log_rec.get("ts")),
            source=src_dev,
            destination=dst_dev,
            sourcePort=src_p,
            destinationPort=dst_p,
            protocol=proto,
            eventType=event_type,
            severity=EventSeverityEnum.INFO,
            detectionSource=DetectionSourceEnum.ZEEK,
            bytes=b_orig + b_resp,
            packets=1,
            metadata={"uid": log_rec.get("uid"), "stream": log_hint or "conn"}
        )
        network_event_validator.assert_valid(event)
        return event

    @classmethod
    def from_simulation(cls, sim_event: Any) -> NetworkEvent:
        if hasattr(sim_event, "model_dump"):
            d = sim_event.model_dump()
        else:
            d = dict(sim_event)

        src_dev = d.get("sourceDevice", "UNKNOWN_DEVICE")
        dst_dev = d.get("destinationDevice", "UNKNOWN_DEVICE")
        src_p = d.get("sourcePort")
        dst_p = d.get("destinationPort")
        proto = str(d.get("protocol", "TCP")).upper()

        event_type = NetworkEventTypeEnum.NETWORK_CONNECTION
        if dst_p == 53:
            event_type = NetworkEventTypeEnum.DNS_QUERY
        elif dst_p == 80:
            event_type = NetworkEventTypeEnum.HTTP_REQUEST
        elif dst_p == 443:
            event_type = NetworkEventTypeEnum.HTTPS_CONNECTION
        elif dst_p == 22:
            event_type = NetworkEventTypeEnum.SSH_CONNECTION

        event = NetworkEvent(
            eventId=event_id_generator.generate(),
            timestamp=cls._parse_ts(d.get("timestamp")),
            source=src_dev,
            destination=dst_dev,
            sourcePort=src_p,
            destinationPort=dst_p,
            protocol=proto,
            eventType=event_type,
            severity=EventSeverityEnum.INFO,
            detectionSource=DetectionSourceEnum.SIMULATION,
            bytes=int(d.get("bytes") or 0),
            packets=int(d.get("packets") or 1),
            metadata={"sim_id": d.get("simulationId")}
        )
        network_event_validator.assert_valid(event)
        return event

network_event_factory = NetworkEventFactory()