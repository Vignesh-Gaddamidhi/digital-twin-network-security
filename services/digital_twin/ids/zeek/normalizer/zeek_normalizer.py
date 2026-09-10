from typing import Dict, Any, Optional
from datetime import datetime, timezone

from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, EventSourceEnum, SecurityEventTypeEnum,
    NormalizedSecuritySeverityEnum
)
from services.digital_twin.ids.zeek.parser.zeek_validator import zeek_validator
from services.digital_twin.ids.processor.device_resolver import twin_device_resolver

class ZeekNormalizer:
    """Normalizes Zeek conn, dns, http, ssl, and ssh logs into standard NormalizedSecurityEvents."""

    @staticmethod
    def infer_log_type(record: Dict[str, Any], default: str = "conn") -> str:
        if "conn_state" in record or "duration" in record:
            return "conn"
        if "query" in record or "qtype_name" in record or "answers" in record:
            return "dns"
        if "method" in record or "uri" in record or "status_code" in record:
            return "http"
        if "server_name" in record or "cipher" in record or "curve" in record:
            return "ssl"
        if "auth_success" in record or "client" in record:
            return "ssh"
        return default

    def normalize(self, record: Dict[str, Any], stream_hint: Optional[str] = None) -> NormalizedSecurityEvent:
        src_ip, dest_ip, src_p, dest_p = zeek_validator.extract_ips_ports(record)
        log_type = stream_hint.lower() if stream_hint else self.infer_log_type(record)

        proto = str(record.get("proto", "TCP")).upper()
        if proto == "-":
            proto = "TCP"

        src_dev = twin_device_resolver.resolve(src_ip or "0.0.0.0", src_p, proto)
        dest_dev = twin_device_resolver.resolve(dest_ip or "0.0.0.0", dest_p, proto)

        # Parse Zeek epoch timestamp if present
        raw_ts = record.get("ts")
        ts = None
        if raw_ts and raw_ts != "-":
            try:
                ts = datetime.fromtimestamp(float(raw_ts), tz=timezone.utc).isoformat()
            except Exception:
                ts = str(raw_ts)

        metadata: Dict[str, Any] = {"zeek_stream": log_type, "raw_uid": record.get("uid")}

        # 1. conn.log
        if log_type == "conn":
            event_type = SecurityEventTypeEnum.FLOW
            severity = NormalizedSecuritySeverityEnum.LOW
            conn_state = record.get("conn_state", "SF")
            orig_bytes = int(record.get("orig_bytes") or 0) if record.get("orig_bytes") not in (None, "-") else 0
            resp_bytes = int(record.get("resp_bytes") or 0) if record.get("resp_bytes") not in (None, "-") else 0
            duration = float(record.get("duration") or 0.0) if record.get("duration") not in (None, "-") else 0.0

            signature = f"Zeek Connection: {proto} {conn_state} ({orig_bytes}B/{resp_bytes}B)"
            category = "Session Accounting"
            metadata.update({
                "conn_state": conn_state,
                "duration": duration,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "history": record.get("history")
            })

        # 2. dns.log
        elif log_type == "dns":
            event_type = SecurityEventTypeEnum.DNS
            severity = NormalizedSecuritySeverityEnum.LOW
            query = record.get("query", "unknown.test")
            qtype = record.get("qtype_name") or record.get("qtype") or "A"
            rcode = record.get("rcode_name") or record.get("rcode") or "NOERROR"

            signature = f"Zeek DNS Query: {query} [{qtype}] ({rcode})"
            category = "Name Resolution Telemetry"
            metadata.update({
                "query": query,
                "qtype": qtype,
                "rcode": rcode,
                "answers": record.get("answers")
            })

        # 3. http.log
        elif log_type == "http":
            event_type = SecurityEventTypeEnum.HTTP
            method = record.get("method", "GET")
            host = record.get("host", "unknown")
            uri = record.get("uri", "/")
            status = int(record.get("status_code") or 200) if record.get("status_code") not in (None, "-") else 200
            severity = NormalizedSecuritySeverityEnum.LOW if status < 400 else NormalizedSecuritySeverityEnum.MEDIUM

            signature = f"Zeek HTTP {method} {host}{uri} [{status}]"
            category = "Web Protocol Transaction"
            metadata.update({
                "method": method,
                "host": host,
                "uri": uri,
                "status_code": status,
                "user_agent": record.get("user_agent")
            })

        # 4. ssl.log
        elif log_type == "ssl":
            event_type = SecurityEventTypeEnum.TLS
            severity = NormalizedSecuritySeverityEnum.LOW
            sni = record.get("server_name") or record.get("sni") or "unknown"
            version = record.get("version", "TLSv1.3")

            signature = f"Zeek TLS Handshake SNI: {sni} ({version})"
            category = "Encrypted Session Audit"
            metadata.update({
                "server_name": sni,
                "version": version,
                "cipher": record.get("cipher"),
                "resumed": record.get("resumed")
            })

        # 5. ssh.log
        elif log_type == "ssh":
            event_type = SecurityEventTypeEnum.SSH
            severity = NormalizedSecuritySeverityEnum.LOW
            auth_success = str(record.get("auth_success", "")).lower() == "true"
            direction = record.get("direction", "INBOUND")

            signature = f"Zeek SSH Session (AuthSuccess={auth_success})"
            category = "Secure Shell Authentication"
            metadata.update({
                "auth_success": auth_success,
                "client": record.get("client"),
                "server": record.get("server")
            })

        else:
            event_type = SecurityEventTypeEnum.PROTOCOL
            severity = NormalizedSecuritySeverityEnum.LOW
            signature = f"Zeek {log_type.upper()} Transaction"
            category = "General Network Telemetry"

        return NormalizedSecurityEvent(
            source=EventSourceEnum.ZEEK,
            eventType=event_type,
            timestamp=ts or datetime.now(timezone.utc).isoformat(),
            sourceDevice=src_dev,
            destinationDevice=dest_dev,
            sourceIP=src_ip or "0.0.0.0",
            destinationIP=dest_ip or "0.0.0.0",
            sourcePort=src_p,
            destinationPort=dest_p,
            protocol=proto,
            severity=severity,
            signature=signature,
            category=category,
            confidence=0.85,
            rawReference=record,
            metadata=metadata
        )

zeek_normalizer = ZeekNormalizer()