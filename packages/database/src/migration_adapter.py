import json
import uuid
from pathlib import Path
from typing import Dict, Any
from datetime import datetime, timezone
from sqlalchemy import select

from packages.database.src.db_connection import db_manager
from packages.database.src.models import Device, TrafficFlow

class MigrationReport:
    def __init__(self):
        self.discovered = 0
        self.migrated = 0
        self.skipped = 0
        self.failed = 0
        self.duplicates = 0
        self.errors = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "discovered": self.discovered,
            "migrated": self.migrated,
            "skipped": self.skipped,
            "failed": self.failed,
            "duplicates": self.duplicates,
            "errors": self.errors
        }

class LegacyDataMigrationAdapter:
    """Migrates historical simulation runs and JSON datasets into PostgreSQL."""

    @staticmethod
    async def migrate_jsonl_events(file_path: Path, max_records: int = 500) -> MigrationReport:
        report = MigrationReport()
        if not file_path.exists():
            report.errors.append(f"File not found: {file_path}")
            return report

        async with db_manager.session() as sess:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if report.migrated >= max_records:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    report.discovered += 1

                    try:
                        data = json.loads(line)
                        src_ip = data.get("source_ip", data.get("src_ip", "10.0.0.1"))
                        dst_ip = data.get("destination_ip", data.get("dst_ip", "10.0.0.2"))
                        src_p = int(data.get("source_port", data.get("src_port", 80)))
                        dst_p = int(data.get("destination_port", data.get("dst_port", 80)))
                        proto = data.get("protocol", "TCP").upper()
                        pkts = int(data.get("packet_count", data.get("packets", 1)))
                        bytes_cnt = int(data.get("byte_count", data.get("bytes", 64)))

                        flow = TrafficFlow(
                            id=str(uuid.uuid4()),
                            timestamp=datetime.now(timezone.utc),
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            source_port=src_p,
                            destination_port=dst_p,
                            protocol=proto,
                            packet_count=pkts,
                            byte_count=bytes_cnt,
                            flow_duration=float(data.get("duration", 0.0)),
                            status="MIGRATED"
                        )
                        sess.add(flow)
                        report.migrated += 1
                    except Exception as e:
                        report.failed += 1
                        report.errors.append(str(e))

            await sess.flush()
        return report

migration_adapter = LegacyDataMigrationAdapter()