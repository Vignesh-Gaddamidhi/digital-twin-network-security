import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from services.digital_twin.ml.dataset.schemas.raw_record_models import (
    RawRecord, RawSourceEnum, DeduplicationStatusEnum, RawIngestionSummary
)
from services.digital_twin.ml.dataset.storage.raw_storage_manager import raw_storage_manager

class RawIngestionEngine:
    """Production ingestion engine capturing raw simulation, Suricata, Zeek, and security events."""

    @staticmethod
    def generate_fingerprint(source: RawSourceEnum, payload: Dict[str, Any]) -> str:
        """Derives a deterministic SHA-256 fingerprint for non-destructive deduplication."""
        # Extract normalized canonical attributes for fingerprint calculation
        ts = str(payload.get("timestamp") or payload.get("ts") or payload.get("eventTimestamp") or "")
        src = str(payload.get("src_ip") or payload.get("id.orig_h") or payload.get("source") or payload.get("sourceDevice") or "")
        dst = str(payload.get("dest_ip") or payload.get("id.resp_h") or payload.get("destination") or payload.get("destinationDevice") or "")
        src_p = str(payload.get("src_port") or payload.get("id.orig_p") or payload.get("sourcePort") or "")
        dst_p = str(payload.get("dest_port") or payload.get("id.resp_p") or payload.get("destinationPort") or payload.get("port") or "")
        proto = str(payload.get("proto") or payload.get("protocol") or "TCP").upper()
        sig = str(payload.get("signature") or payload.get("alert", {}).get("signature") if isinstance(payload.get("alert"), dict) else "")

        key_components = f"{source.value}::{ts}::{src}:{src_p}->{dst}:{dst_p}::{proto}::{sig}"
        return hashlib.sha256(key_components.encode("utf-8")).hexdigest()

    @staticmethod
    def validate_raw_record(source: RawSourceEnum, payload: Any) -> Tuple[bool, List[str]]:
        errors = []
        if not isinstance(payload, dict):
            return False, ["Payload must be a key-value dictionary"]

        if not payload:
            return False, ["Empty payload"]

        # Timestamp presence check
        has_ts = any(k in payload for k in ("timestamp", "ts", "eventTimestamp", "createdAt"))
        if not has_ts:
            errors.append("Missing timestamp field ('timestamp', 'ts', or 'eventTimestamp')")

        # Endpoint presence check
        has_src = any(k in payload for k in ("src_ip", "id.orig_h", "source", "sourceDevice", "sourceIP"))
        has_dst = any(k in payload for k in ("dest_ip", "id.resp_h", "destination", "destinationDevice", "destinationIP"))
        if not has_src:
            errors.append("Missing source identifier")
        if not has_dst:
            errors.append("Missing destination identifier")

        return len(errors) == 0, errors

    def ingest_record(self, source: RawSourceEnum, payload: Dict[str, Any], source_file: Optional[str] = None) -> RawRecord:
        is_valid, errors = self.validate_raw_record(source, payload)
        fingerprint = self.generate_fingerprint(source, payload)
        orig_ts = str(payload.get("timestamp") or payload.get("ts") or payload.get("eventTimestamp") or "")

        rec = RawRecord(
            source=source,
            sourceFile=source_file,
            originalTimestamp=orig_ts if orig_ts else None,
            fingerprint=fingerprint,
            rawPayload=payload,
            validationStatus="VALID" if is_valid else "INVALID",
            validationErrors=errors
        )
        return raw_storage_manager.store_record(rec)

    def load_simulation_events(self, events: List[Dict[str, Any]], source_file: str = "simulation_events.jsonl") -> RawIngestionSummary:
        return self._ingest_batch(RawSourceEnum.SIMULATION, events, source_file)

    def load_suricata_events(self, events: List[Dict[str, Any]], source_file: str = "eve.json") -> RawIngestionSummary:
        return self._ingest_batch(RawSourceEnum.SURICATA, events, source_file)

    def load_zeek_events(self, events: List[Dict[str, Any]], source_file: str = "conn.log") -> RawIngestionSummary:
        return self._ingest_batch(RawSourceEnum.ZEEK, events, source_file)

    def load_security_events(self, events: List[Dict[str, Any]], source_file: str = "security_events.json") -> RawIngestionSummary:
        return self._ingest_batch(RawSourceEnum.SECURITY_PIPELINE, events, source_file)

    def _ingest_batch(self, source: RawSourceEnum, events: List[Dict[str, Any]], source_file: str) -> RawIngestionSummary:
        summary = RawIngestionSummary(source=source, sourceFile=source_file, totalRead=len(events))

        for raw_item in events:
            rec = self.ingest_record(source, raw_item, source_file=source_file)
            if rec.validationStatus == "VALID":
                summary.validRecords += 1
            else:
                summary.invalidRecords += 1

            if rec.deduplicationStatus == DeduplicationStatusEnum.DUPLICATE:
                summary.duplicatesDetected += 1
            else:
                summary.persistedCount += 1

        return summary

raw_ingestion_engine = RawIngestionEngine()