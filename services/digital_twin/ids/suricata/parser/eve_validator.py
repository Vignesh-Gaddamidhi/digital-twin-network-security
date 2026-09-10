import ipaddress
from typing import Dict, Any, Tuple, Optional

SUPPORTED_EVENT_TYPES = {"alert", "flow", "dns", "http", "tls", "ssh", "fileinfo", "stats"}

class EveEventValidator:
    """Validates raw parsed Suricata EVE records against structural invariants."""

    @staticmethod
    def validate(record: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not isinstance(record, dict):
            return False, "EVE record must be a JSON object"

        # 1. Check mandatory fields
        required_fields = ["timestamp", "event_type", "src_ip", "dest_ip", "proto"]
        for rf in required_fields:
            val = record.get(rf)
            if val is None or str(val).strip() == "":
                return False, f"Missing required field '{rf}'"

        # 2. Validate IP addresses
        src_ip = record.get("src_ip", "")
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            return False, f"Invalid source IP address format: '{src_ip}'"

        dest_ip = record.get("dest_ip", "")
        try:
            ipaddress.ip_address(dest_ip)
        except ValueError:
            return False, f"Invalid destination IP address format: '{dest_ip}'"

        # 3. Validate event type
        evt_type = str(record.get("event_type", "")).lower()
        if evt_type not in SUPPORTED_EVENT_TYPES:
            return False, f"Unknown or unsupported event_type: '{evt_type}'"

        # 4. Category-specific nested structure checks
        if evt_type == "alert":
            alert_obj = record.get("alert")
            if not isinstance(alert_obj, dict):
                return False, "Malformed event: 'alert' field must be a dictionary"
            if not alert_obj.get("signature"):
                return False, "Malformed alert: Missing required 'signature' inside alert object"

        elif evt_type == "dns":
            dns_obj = record.get("dns")
            if not isinstance(dns_obj, dict):
                return False, "Malformed event: 'dns' field must be a dictionary"

        elif evt_type == "http":
            http_obj = record.get("http")
            if not isinstance(http_obj, dict):
                return False, "Malformed event: 'http' field must be a dictionary"

        elif evt_type == "tls":
            tls_obj = record.get("tls")
            if not isinstance(tls_obj, dict):
                return False, "Malformed event: 'tls' field must be a dictionary"

        return True, None

eve_validator = EveEventValidator()