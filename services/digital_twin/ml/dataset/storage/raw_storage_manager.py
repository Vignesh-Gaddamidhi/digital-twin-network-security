import json
from pathlib import Path
from typing import List, Dict, Optional, Set

from services.digital_twin.ml.dataset.schemas.raw_record_models import RawRecord, RawSourceEnum, DeduplicationStatusEnum

ROOT_DIR = Path(__file__).resolve().parents[6]
RAW_STORAGE_DIR = ROOT_DIR / "datasets" / "raw"

class RawStorageManager:
    """Manages appending and indexing raw ingested records in datasets/raw/."""

    def __init__(self, base_dir: Path = RAW_STORAGE_DIR):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._fingerprints: Dict[str, str] = {}  # fingerprint -> rawRecordId
        self._in_memory_records: List[RawRecord] = []

    def _get_file_path(self, source: RawSourceEnum) -> Path:
        return self.base_dir / f"{source.value.lower()}_raw.jsonl"

    def store_record(self, record: RawRecord) -> RawRecord:
        # Check duplicate fingerprint
        if record.fingerprint in self._fingerprints:
            record.deduplicationStatus = DeduplicationStatusEnum.DUPLICATE
            record.duplicateOf = self._fingerprints[record.fingerprint]
        else:
            self._fingerprints[record.fingerprint] = record.rawRecordId

        self._in_memory_records.append(record)

        # Append to persistent JSONL
        out_file = self._get_file_path(record.source)
        with open(out_file, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")

        return record

    def get_record(self, raw_record_id: str) -> Optional[RawRecord]:
        for r in self._in_memory_records:
            if r.rawRecordId == raw_record_id:
                return r
        return None

    def list_records(self, source: Optional[RawSourceEnum] = None, exclude_duplicates: bool = False) -> List[RawRecord]:
        recs = self._in_memory_records
        if source:
            recs = [r for r in recs if r.source == source]
        if exclude_duplicates:
            recs = [r for r in recs if r.deduplicationStatus == DeduplicationStatusEnum.ORIGINAL]
        return recs

    def clear(self):
        self._fingerprints.clear()
        self._in_memory_records.clear()
        for f in self.base_dir.glob("*.jsonl"):
            try:
                f.unlink()
            except Exception:
                pass

raw_storage_manager = RawStorageManager()