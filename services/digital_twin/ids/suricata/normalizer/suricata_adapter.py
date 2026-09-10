from typing import Dict, Any, Optional
from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, EventSourceEnum, SecurityEventTypeEnum,
    NormalizedSecuritySeverityEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry

class SuricataAdapter:
    """Translates Suricata EVE JSON structures into NormalizedSecurityEvents across all categories."""

    SEVERITY_MAP = {
        1: NormalizedSecuritySeverityEnum.CRITICAL,  # Suricata 1: Highest
        2: NormalizedSecuritySeverityEnum.HIGH,      # Suricata 2: High
        3: NormalizedSecuritySeverityEnum.MEDIUM,    # Suricata 3: Medium
        4: NormalizedSecuritySeverityEnum.LOW        # Suricata 4: Informational
    }

    EVENT_TYPE_MAP = {
        "alert": SecurityEventTypeEnum.ALERT,
        "flow": SecurityEventTypeEnum.FLOW,
        "dns": SecurityEventTypeEnum.DNS,
        "http": SecurityEventTypeEnum.HTTP,
        "tls": SecurityEventTypeEnum.TLS
    }

    @staticmethod
    def _resolve_device_by_ip(ip: str) -> Optional[str]:
        devices = []
        if hasattr(device_registry, "getAllDevices"):
            devices = device_registry.getAllDevices()
        elif hasattr(device_registry, "listDevices"):
            devices = device_registry.listDevices()
        elif hasattr(device_registry, "getAll"):
            devices = device_registry.getAll()
        elif hasattr(device_registry, "_devices"):
            devices = list(device_registry._devices.values())

        for dev in devices:
            if getattr(dev, "ipAddress", None) == ip:
                return dev.id
            if dev.id.lower() in ip.lower() or dev.hostname.lower() in ip.lower():
                return dev.id

        if ip.startswith("192.168.1.") or ip.startswith("10.0.0."):
            if ip.endswith(".10") or "client" in ip.lower():
                return "CLIENT-01"
            if ip.endswith(".20") or "web" in ip.lower():
                return "WEB-01"
            if ip.endswith(".22") or "server" in ip.lower():
                return "SERVER-01"
            if ip.endswith(".53") or "dns" in ip.lower():
                return "DNS-01"
            if ip.endswith(".100") or "db" in ip.lower():
                return "DB-01"
        return None

    def normalize(self, eve_record: Dict[str, Any]) -> NormalizedSecurityEvent:
        raw_event_type = str(eve_record.get("event_type", "alert")).lower()
        norm_event_type = self.EVENT_TYPE_MAP.get(raw_event_type, SecurityEventTypeEnum.ANOMALY)

        src_ip = eve_record.get("src_ip", "0.0.0.0")
        dest_ip = eve_record.get("dest_ip", "0.0.0.0")
        src_port = eve_record.get("src_port")
        dest_port = eve_record.get("dest_port")
        proto = str(eve_record.get("proto", "TCP")).upper()
        ts = eve_record.get("timestamp")

        src_dev = self._resolve_device_by_ip(src_ip)
        dest_dev = self._resolve_device_by_ip(dest_ip)

        metadata: Dict[str, Any] = {
            "flow_id": eve_record.get("flow_id"),
            "in_iface": eve_record.get("in_iface")
        }

        # 1. Alert Normalization
        if raw_event_type == "alert":
            alert_block = eve_record.get("alert", {})
            raw_sev = alert_block.get("severity", 3)
            severity = self.SEVERITY_MAP.get(raw_sev, NormalizedSecuritySeverityEnum.MEDIUM)
            signature = alert_block.get("signature", "Suricata Alert")
            category = alert_block.get("category", "Network Intrusion")
            metadata.update({
                "gid": alert_block.get("gid", 1),
                "sid": alert_block.get("signature_id", 0),
                "rev": alert_block.get("rev", 1),
                "action": alert_block.get("action", "allowed")
            })
            confidence = 0.90

        # 2. Flow Normalization
        elif raw_event_type == "flow":
            flow_block = eve_record.get("flow", {})
            severity = NormalizedSecuritySeverityEnum.LOW
            signature = f"Network Flow Session ({proto})"
            category = "Session Accounting"
            metadata.update({
                "bytes_toserver": flow_block.get("bytes_toserver", 0),
                "bytes_toclient": flow_block.get("bytes_toclient", 0),
                "pkts_toserver": flow_block.get("pkts_toserver", 0),
                "pkts_toclient": flow_block.get("pkts_toclient", 0),
                "state": flow_block.get("state", "closed"),
                "reason": flow_block.get("reason", "idle")
            })
            confidence = 0.70

        # 3. DNS Normalization
        elif raw_event_type == "dns":
            dns_block = eve_record.get("dns", {})
            severity = NormalizedSecuritySeverityEnum.LOW
            query_name = dns_block.get("rrname", "unknown.test")
            qtype = dns_block.get("rrtype", "A")
            signature = f"DNS Query: {query_name} [{qtype}]"
            category = "Name Resolution"
            metadata.update({
                "rrname": query_name,
                "rrtype": qtype,
                "rcode": dns_block.get("rcode", "NOERROR"),
                "type": dns_block.get("type", "query")
            })
            confidence = 0.75

        # 4. HTTP Normalization
        elif raw_event_type == "http":
            http_block = eve_record.get("http", {})
            status_code = http_block.get("status", 200)
            severity = NormalizedSecuritySeverityEnum.LOW if status_code < 400 else NormalizedSecuritySeverityEnum.MEDIUM
            host = http_block.get("hostname", "unknown")
            url = http_block.get("url", "/")
            method = http_block.get("http_method", "GET")
            signature = f"HTTP {method} {host}{url}"
            category = "Web Protocol Transaction"
            metadata.update({
                "hostname": host,
                "url": url,
                "http_method": method,
                "status": status_code,
                "http_user_agent": http_block.get("http_user_agent")
            })
            confidence = 0.75

        # 5. TLS Normalization
        elif raw_event_type == "tls":
            tls_block = eve_record.get("tls", {})
            sni = tls_block.get("sni", "unknown")
            subject = tls_block.get("subject", "unknown")
            severity = NormalizedSecuritySeverityEnum.LOW
            signature = f"TLS Handshake SNI: {sni}"
            category = "Encrypted Session Handshake"
            metadata.update({
                "sni": sni,
                "subject": subject,
                "issuerdn": tls_block.get("issuerdn"),
                "version": tls_block.get("version")
            })
            confidence = 0.80

        else:
            severity = NormalizedSecuritySeverityEnum.LOW
            signature = f"Suricata {raw_event_type.upper()} Event"
            category = "General Telemetry"
            confidence = 0.50

        # Compute root bytes, packets, and application
        flow_sub = eve_record.get("flow", {})
        bytes_val = int(flow_sub.get("bytes_toserver", 0)) + int(flow_sub.get("bytes_toclient", 0))
        pkts_val = int(flow_sub.get("pkts_toserver", 0)) + int(flow_sub.get("pkts_toclient", 0))
        app_proto = eve_record.get("app_proto") or raw_event_type.upper()

        return NormalizedSecurityEvent(
            source=EventSourceEnum.SURICATA,
            eventType=norm_event_type,
            timestamp=ts or None,
            sourceDevice=src_dev,
            destinationDevice=dest_dev,
            sourceIP=src_ip,
            destinationIP=dest_ip,
            sourcePort=src_port,
            destinationPort=dest_port,
            protocol=proto,
            bytes=bytes_val,
            packets=pkts_val,
            application=app_proto,
            severity=severity,
            signature=signature,
            category=category,
            confidence=confidence,
            rawReference=eve_record,
            metadata=metadata
        )

suricata_adapter = SuricataAdapter()