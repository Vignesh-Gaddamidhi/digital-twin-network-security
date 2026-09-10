import ipaddress
from typing import Dict, Any, Tuple, Optional

class ZeekValidator:
    """Validates raw Zeek log records across conn, dns, http, ssl, and ssh streams."""

    @staticmethod
    def extract_ips_ports(record: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        # Check standard JSON nested notation or flat TSV dotted notation
        src_ip = record.get("id.orig_h") or record.get("src_ip") or record.get("orig_h")
        dest_ip = record.get("id.resp_h") or record.get("dest_ip") or record.get("resp_h")

        # Nested dict check: {"id": {"orig_h": "...", ...}}
        if not src_ip and isinstance(record.get("id"), dict):
            src_ip = record["id"].get("orig_h")
            dest_ip = record["id"].get("resp_h")

        src_p = record.get("id.orig_p") or record.get("src_port") or record.get("orig_p")
        dest_p = record.get("id.resp_p") or record.get("dest_port") or record.get("resp_p")
        if src_p is None and isinstance(record.get("id"), dict):
            src_p = record["id"].get("orig_p")
            dest_p = record["id"].get("resp_p")

        try:
            src_p = int(src_p) if src_p is not None else None
        except (ValueError, TypeError):
            src_p = None

        try:
            dest_p = int(dest_p) if dest_p is not None else None
        except (ValueError, TypeError):
            dest_p = None

        return src_ip, dest_ip, src_p, dest_p

    def validate(self, record: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not isinstance(record, dict):
            return False, "Zeek record must be a key-value dictionary"

        src_ip, dest_ip, _, _ = self.extract_ips_ports(record)

        if not src_ip or str(src_ip).strip() in ("", "-"):
            return False, "Missing origin/source IP address ('id.orig_h')"
        if not dest_ip or str(dest_ip).strip() in ("", "-"):
            return False, "Missing responder/destination IP address ('id.resp_h')"

        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            return False, f"Invalid source IP address format: '{src_ip}'"

        try:
            ipaddress.ip_address(dest_ip)
        except ValueError:
            return False, f"Invalid destination IP address format: '{dest_ip}'"

        return True, None

zeek_validator = ZeekValidator()