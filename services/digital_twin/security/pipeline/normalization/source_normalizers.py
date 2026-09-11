import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from services.digital_twin.security.pipeline.normalization.canonical_event import (
    CanonicalEvent, CanonicalDetectionSourceEnum, CanonicalSeverityEnum, CanonicalProtocolEnum
)
from services.digital_twin.ids.processor.device_resolver import twin_device_resolver

class NormalizationError(Exception):
    pass

class BaseSourceNormalizer:
    """Helper methods for timestamp, protocol, and port coercion."""

    @staticmethod
    def parse_timestamp(raw_ts: Any) -> str:
        if raw_ts is None or str(raw_ts).strip() in ("", "-", "null"):
            raise NormalizationError("Missing or null event timestamp")

        # Unix numeric timestamp (epoch seconds / milliseconds / microseconds)
        if isinstance(raw_ts, (int, float)):
            try:
                val = float(raw_ts)
                if val > 1e11:
                    val /= 1000.0
                return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
            except Exception as e:
                raise NormalizationError(f"Invalid epoch timestamp: {e}")

        ts_str = str(raw_ts).strip()
        if re.match(r"^\d+(\.\d+)?$", ts_str):
            try:
                val = float(ts_str)
                if val > 1e11:
                    val /= 1000.0
                return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
            except Exception as e:
                raise NormalizationError(f"Invalid string epoch timestamp: {e}")

        try:
            clean = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception as e:
            raise NormalizationError(f"Invalid ISO timestamp format '{ts_str}': {e}")

    @staticmethod
    def parse_protocol(raw_proto: Any) -> CanonicalProtocolEnum:
        if raw_proto is None:
            raise NormalizationError("Missing protocol field")
        p = str(raw_proto).strip().upper()
        if p in ("TCP", "6"):
            return CanonicalProtocolEnum.TCP
        elif p in ("UDP", "17"):
            return CanonicalProtocolEnum.UDP
        elif p in ("ICMP", "1"):
            return CanonicalProtocolEnum.ICMP
        raise NormalizationError(f"Unsupported or unknown protocol '{raw_proto}'")

    @staticmethod
    def parse_port(raw_port: Any) -> Optional[int]:
        if raw_port is None or str(raw_port).strip() in ("", "-", "null"):
            return None
        try:
            val = int(float(str(raw_port).strip()))
            if not (0 <= val <= 65535):
                raise NormalizationError(f"Port {val} out of bounds (0-65535)")
            return val
        except ValueError:
            raise NormalizationError(f"Port '{raw_port}' is not a valid integer")

    @classmethod
    def resolve_endpoints(cls, src: str, dst: str, src_p: Optional[int], dst_p: Optional[int], proto: str) -> Tuple[str, str]:
        if not src or str(src).strip() in ("", "-"):
            raise NormalizationError("Missing source endpoint")
        if not dst or str(dst).strip() in ("", "-"):
            raise NormalizationError("Missing destination endpoint")

        resolved_src = twin_device_resolver.resolve(str(src).strip(), src_p, proto)
        resolved_dst = twin_device_resolver.resolve(str(dst).strip(), dst_p, proto)
        return resolved_src, resolved_dst


class SuricataNormalizer(BaseSourceNormalizer):
    """Normalizes raw Suricata EVE JSON records into CanonicalEvent."""

    def normalize(self, eve: Dict[str, Any]) -> CanonicalEvent:
        if not isinstance(eve, dict):
            raise NormalizationError("Suricata record must be a dictionary")

        event_ts = self.parse_timestamp(eve.get("timestamp"))
        proto = self.parse_protocol(eve.get("proto", "TCP"))
        src_p = self.parse_port(eve.get("src_port"))
        dst_p = self.parse_port(eve.get("dest_port"))

        raw_src = eve.get("src_ip")
        raw_dst = eve.get("dest_ip")
        resolved_src, resolved_dst = self.resolve_endpoints(raw_src, raw_dst, src_p, dst_p, proto.value)

        # Infer raw type cleanly
        alert_obj = eve.get("alert")
        if "event_type" in eve:
            raw_type = str(eve["event_type"]).lower()
        else:
            raw_type = "alert" if isinstance(alert_obj, dict) else "flow"

        severity = CanonicalSeverityEnum.INFO
        signature = None

        if raw_type == "alert":
            if isinstance(alert_obj, dict):
                event_type = "IDS_ALERT"
                signature = alert_obj.get("signature", "Suricata Alert")
                raw_sev = alert_obj.get("severity", 3)
                sev_map = {1: CanonicalSeverityEnum.CRITICAL, 2: CanonicalSeverityEnum.HIGH, 3: CanonicalSeverityEnum.MEDIUM, 4: CanonicalSeverityEnum.LOW}
                severity = sev_map.get(raw_sev, CanonicalSeverityEnum.MEDIUM)
            elif eve.get("event_type") == "alert":
                raise NormalizationError("Suricata alert event missing 'alert' dictionary")
            else:
                event_type = "NETWORK_CONNECTION"
        elif raw_type == "dns":
            event_type = "DNS_QUERY"
        elif raw_type == "http":
            event_type = "HTTP_REQUEST"
        elif raw_type == "tls":
            event_type = "HTTPS_CONNECTION"
        elif dst_p == 22 or src_p == 22:
            event_type = "SSH_CONNECTION"
        else:
            event_type = "NETWORK_CONNECTION"

        flow_b = eve.get("flow", {})
        flow_bytes = int(flow_b.get("bytes_toserver", 0)) + int(flow_b.get("bytes_toclient", 0))
        flow_pkts = int(flow_b.get("pkts_toserver", 0)) + int(flow_b.get("pkts_toclient", 0))
        bytes_val = int(eve.get("bytes") or flow_bytes or 0)
        pkts_val = int(eve.get("packets") or flow_pkts or 1)

        suri_meta = {"raw_eve_type": raw_type, "flow_id": eve.get("flow_id")}
        if isinstance(eve.get("metadata"), dict):
            suri_meta.update(eve.get("metadata"))
        if "direction" in eve:
            suri_meta["direction"] = eve.get("direction")

        return CanonicalEvent(
            eventTimestamp=event_ts,
            source=resolved_src,
            destination=resolved_dst,
            protocol=proto,
            port=dst_p,
            sourcePort=src_p,
            eventType=event_type,
            severity=severity,
            detectionSource=CanonicalDetectionSourceEnum.SURICATA,
            bytes=bytes_val,
            packets=max(1, pkts_val),
            signature=signature,
            metadata=suri_meta
        )


class ZeekNormalizer(BaseSourceNormalizer):
    """Normalizes raw Zeek log records (JSON or mapped dict) into CanonicalEvent."""

    def normalize(self, zeek_rec: Dict[str, Any], stream_hint: Optional[str] = None) -> CanonicalEvent:
        if not isinstance(zeek_rec, dict):
            raise NormalizationError("Zeek record must be a dictionary")

        raw_ts = zeek_rec.get("ts") if zeek_rec.get("ts") is not None else zeek_rec.get("timestamp")
        event_ts = self.parse_timestamp(raw_ts)

        proto = self.parse_protocol(zeek_rec.get("proto", "tcp"))
        src_p = self.parse_port(zeek_rec.get("id.orig_p") or zeek_rec.get("src_port") or (zeek_rec.get("id", {}).get("orig_p") if isinstance(zeek_rec.get("id"), dict) else None))
        dst_p = self.parse_port(zeek_rec.get("id.resp_p") or zeek_rec.get("dest_port") or (zeek_rec.get("id", {}).get("resp_p") if isinstance(zeek_rec.get("id"), dict) else None))

        raw_src = zeek_rec.get("id.orig_h") or zeek_rec.get("src_ip") or (zeek_rec.get("id", {}).get("orig_h") if isinstance(zeek_rec.get("id"), dict) else None)
        raw_dst = zeek_rec.get("id.resp_h") or zeek_rec.get("dest_ip") or (zeek_rec.get("id", {}).get("resp_h") if isinstance(zeek_rec.get("id"), dict) else None)
        resolved_src, resolved_dst = self.resolve_endpoints(raw_src, raw_dst, src_p, dst_p, proto.value)

        log_hint = (stream_hint or "").lower()
        if "query" in zeek_rec or log_hint == "dns" or dst_p == 53:
            event_type = "DNS_QUERY"
        elif "method" in zeek_rec or log_hint == "http" or dst_p == 80:
            event_type = "HTTP_REQUEST"
        elif "server_name" in zeek_rec or log_hint in ("ssl", "tls") or dst_p == 443:
            event_type = "HTTPS_CONNECTION"
        elif "auth_success" in zeek_rec or log_hint == "ssh" or dst_p == 22:
            event_type = "SSH_CONNECTION"
        else:
            event_type = "NETWORK_CONNECTION"

        b_orig = int(zeek_rec.get("orig_bytes") or 0) if zeek_rec.get("orig_bytes") not in (None, "-") else 0
        b_resp = int(zeek_rec.get("resp_bytes") or 0) if zeek_rec.get("resp_bytes") not in (None, "-") else 0

        zeek_meta = {"uid": zeek_rec.get("uid"), "conn_state": zeek_rec.get("conn_state")}
        if isinstance(zeek_rec.get("metadata"), dict):
            zeek_meta.update(zeek_rec.get("metadata"))
        if "direction" in zeek_rec:
            zeek_meta["direction"] = zeek_rec.get("direction")

        return CanonicalEvent(
            eventTimestamp=event_ts,
            source=resolved_src,
            destination=resolved_dst,
            protocol=proto,
            port=dst_p,
            sourcePort=src_p,
            eventType=event_type,
            severity=CanonicalSeverityEnum.INFO,
            detectionSource=CanonicalDetectionSourceEnum.ZEEK,
            bytes=b_orig + b_resp,
            packets=1,
            metadata=zeek_meta
        )


class SimulationNormalizer(BaseSourceNormalizer):
    """Normalizes synthetic Digital Twin simulation events into CanonicalEvent."""

    def normalize(self, sim: Dict[str, Any]) -> CanonicalEvent:
        if not isinstance(sim, dict):
            raise NormalizationError("Simulation event must be a dictionary")

        event_ts = self.parse_timestamp(sim.get("timestamp"))
        proto = self.parse_protocol(sim.get("protocol", "TCP"))
        src_p = self.parse_port(sim.get("sourcePort") or sim.get("src_port"))
        dst_p = self.parse_port(sim.get("destinationPort") or sim.get("dest_port"))

        raw_src = sim.get("sourceDevice") or sim.get("source") or sim.get("src_ip")
        raw_dst = sim.get("destinationDevice") or sim.get("destination") or sim.get("dest_ip")
        resolved_src, resolved_dst = self.resolve_endpoints(raw_src, raw_dst, src_p, dst_p, proto.value)

        event_type = sim.get("eventType")
        if not event_type:
            if dst_p == 53:
                event_type = "DNS_QUERY"
            elif dst_p == 80:
                event_type = "HTTP_REQUEST"
            elif dst_p == 443:
                event_type = "HTTPS_CONNECTION"
            elif dst_p == 22:
                event_type = "SSH_CONNECTION"
            else:
                event_type = "NETWORK_CONNECTION"

        raw_sev = str(sim.get("severity", "INFO")).upper()
        severity = getattr(CanonicalSeverityEnum, raw_sev, CanonicalSeverityEnum.INFO)

        sim_meta = {"sim_id": sim.get("simulationId")}
        if isinstance(sim.get("metadata"), dict):
            sim_meta.update(sim.get("metadata"))
        if "direction" in sim:
            sim_meta["direction"] = sim.get("direction")

        return CanonicalEvent(
            eventTimestamp=event_ts,
            source=resolved_src,
            destination=resolved_dst,
            protocol=proto,
            port=dst_p,
            sourcePort=src_p,
            eventType=str(event_type),
            severity=severity,
            detectionSource=CanonicalDetectionSourceEnum.SIMULATION,
            bytes=int(sim.get("bytes") or 0),
            packets=int(sim.get("packets") or 1),
            signature=sim.get("signature"),
            metadata=sim_meta
        )

suricata_normalizer = SuricataNormalizer()
zeek_normalizer = ZeekNormalizer()
simulation_normalizer = SimulationNormalizer()