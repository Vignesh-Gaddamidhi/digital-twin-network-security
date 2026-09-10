from typing import List, Optional, Dict, Any
from pathlib import Path

from packages.shared_types.src.normalized_security_event import NormalizedSecurityEvent
from services.digital_twin.ids.schemas.eve_pipeline_types import (
    MalformedEveRecord, EvePipelineIngestResult
)
from services.digital_twin.ids.zeek.parser.zeek_parser import zeek_parser
from services.digital_twin.ids.zeek.parser.zeek_validator import zeek_validator
from services.digital_twin.ids.zeek.normalizer.zeek_normalizer import zeek_normalizer
from services.digital_twin.ids.processor.ids_processor import ids_processor
from services.digital_twin.ids.processor.twin_event_processor import suricata_twin_processor
from services.digital_twin.ids.processor.multi_source_processor import multi_source_processor

class ZeekCollector:
    """Production Zeek log ingestion collector supporting conn, dns, http, ssl, and ssh streams."""

    def __init__(self):
        self.malformed_queue: List[MalformedEveRecord] = []
        self.normalized_events: List[NormalizedSecurityEvent] = []

    def collect_from_records(self, raw_records: List[Dict[str, Any]], stream_hint: Optional[str] = None) -> EvePipelineIngestResult:
        result = EvePipelineIngestResult()

        for idx, rec in enumerate(raw_records, start=1):
            result.totalProcessed += 1

            is_valid, validation_err = zeek_validator.validate(rec)
            if not is_valid:
                malformed = MalformedEveRecord(
                    rawInput=str(rec),
                    lineNumber=idx,
                    errorReason=validation_err or "Zeek validation check failed",
                    details=rec
                )
                self.malformed_queue.append(malformed)
                result.malformedRecords.append(malformed)
                result.malformedCount += 1
                continue

            try:
                norm_evt = zeek_normalizer.normalize(rec, stream_hint=stream_hint)
                self.normalized_events.append(norm_evt)
                ids_processor.processed_events.append(norm_evt)
                ids_processor._apply_event_to_twin(norm_evt)
                suricata_twin_processor.processEvent(norm_evt)
                multi_source_processor.process(norm_evt)

                result.validCount += 1
                result.normalizedEventIds.append(norm_evt.eventId)
            except Exception as e:
                malformed = MalformedEveRecord(
                    rawInput=str(rec),
                    lineNumber=idx,
                    errorReason=f"Zeek Normalization Error: {str(e)}",
                    details=rec
                )
                self.malformed_queue.append(malformed)
                result.malformedRecords.append(malformed)
                result.malformedCount += 1

        return result

    def collect_from_string(self, log_text: str, stream_hint: Optional[str] = None) -> EvePipelineIngestResult:
        records = zeek_parser.parse_log(log_text)
        if not records:
            # Check if invalid non-empty string was sent
            stripped = log_text.strip()
            if stripped and not stripped.startswith("#"):
                res = EvePipelineIngestResult(totalProcessed=1, malformedCount=1)
                m = MalformedEveRecord(rawInput=stripped, lineNumber=1, errorReason="Invalid Zeek JSON/TSV format")
                self.malformed_queue.append(m)
                res.malformedRecords.append(m)
                return res
        return self.collect_from_records(records, stream_hint=stream_hint)

    def collect_from_file(self, file_path: Path, stream_hint: Optional[str] = None) -> EvePipelineIngestResult:
        if not file_path.exists():
            raise FileNotFoundError(f"Zeek log file not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            return self.collect_from_string(f.read(), stream_hint=stream_hint)

    def clear(self):
        self.malformed_queue.clear()
        self.normalized_events.clear()

zeek_collector = ZeekCollector()