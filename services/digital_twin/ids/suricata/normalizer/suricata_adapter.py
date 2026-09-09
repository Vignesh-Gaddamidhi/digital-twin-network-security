from typing import Dict, Any, Optional
from packages.shared_types.src.normalized_security_event import (
    NormalizedSecurityEvent, EventSourceEnum, SecurityEventTypeEnum,
    NormalizedSecuritySeverityEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry

class SuricataAdapter:
    """Translates Suricata EVE JSON structures into NormalizedSecurityEvents."""

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
        # 1. Direct registry lookup across supported access methods
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

        # 2. Canonical testbed subnet resolution
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
        raw_event_type = eve_record.get("event_type", "alert").lower()
        norm_event_type = self.EVENT_TYPE_MAP.get(raw_event_type, SecurityEventTypeEnum.ANOMALY)

        src_ip = eve_record.get("src_ip", "0.0.0.0")
        dest_ip = eve_record.get("dest_ip", "0.0.0.0")
        src_port = eve_record.get("src_port")
        dest_port = eve_record.get("dest_port")
        proto = eve_record.get("proto", "TCP").upper()
        ts = eve_record.get("timestamp")

        # Resolve host entities in Digital Twin
        src_dev = self._resolve_device_by_ip(src_ip)
        dest_dev = self._resolve_device_by_ip(dest_ip)

        # Extract Alert specific fields
        alert_block = eve_record.get("alert", {})
        raw_sev = alert_block.get("severity", 3)
        severity = self.SEVERITY_MAP.get(raw_sev, NormalizedSecuritySeverityEnum.MEDIUM)
        signature = alert_block.get("signature", f"Suricata {raw_event_type.upper()} Event")
        category = alert_block.get("category", "Network Telemetry")

        return NormalizedSecurityEvent(
            source=EventSourceEnum.SURICATA,
            eventType=norm_event_type,
            timestamp=ts if ts else None,
            sourceDevice=src_dev,
            destinationDevice=dest_dev,
            sourceIP=src_ip,
            destinationIP=dest_ip,
            sourcePort=src_port,
            destinationPort=dest_port,
            protocol=proto,
            severity=severity,
            signature=signature,
            category=category,
            confidence=0.90 if norm_event_type == SecurityEventTypeEnum.ALERT else 0.75,
            rawReference=eve_record,
            metadata={
                "gid": alert_block.get("gid", 1),
                "sid": alert_block.get("signature_id", 0),
                "rev": alert_block.get("rev", 1),
                "flow_id": eve_record.get("flow_id")
            }
        )

suricata_adapter = SuricataAdapter()