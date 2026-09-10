import json
from typing import Dict, Any, List, Optional

class ZeekParser:
    """Parses Zeek streaming JSON and standard tab-delimited (#fields) TSV logs."""

    @staticmethod
    def parse_json_line(line: str) -> Optional[Dict[str, Any]]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return None

    @classmethod
    def parse_tsv(cls, tsv_text: str) -> List[Dict[str, Any]]:
        records = []
        fields = []
        separator = "\t"

        for line in tsv_text.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("#separator"):
                # Handle hex separator definition if present e.g. #separator \x09
                if "\\x09" in line:
                    separator = "\t"
                continue

            if line.startswith("#fields"):
                fields = line.split()[1:]
                continue

            if line.startswith("#"):
                continue

            if fields:
                tokens = line.split(separator)
                if len(tokens) == len(fields):
                    row: Dict[str, Any] = {}
                    for k, v in zip(fields, tokens):
                        # Zeek null placeholder is '-'
                        row[k] = None if v == "-" else v
                    records.append(row)

        return records

    @classmethod
    def parse_log(cls, text: str) -> List[Dict[str, Any]]:
        stripped = text.strip()
        if stripped.startswith("{"):
            records = []
            for line in stripped.splitlines():
                rec = cls.parse_json_line(line)
                if rec:
                    records.append(rec)
            return records
        return cls.parse_tsv(text)

zeek_parser = ZeekParser()