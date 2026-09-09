import json
from typing import Dict, Any, Optional, List

class SuricataEveParseError(Exception):
    pass

class SuricataEveParser:
    """Parses raw Suricata EVE JSON records and line streams."""

    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as e:
            raise SuricataEveParseError(f"Invalid Suricata EVE JSON string: {e}")

    @classmethod
    def parse_records(cls, text: str) -> List[Dict[str, Any]]:
        records = []
        for line in text.strip().splitlines():
            rec = cls.parse_line(line)
            if rec:
                records.append(rec)
        return records

suricata_eve_parser = SuricataEveParser()