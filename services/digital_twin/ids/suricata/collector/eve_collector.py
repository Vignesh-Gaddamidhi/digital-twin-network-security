import json
from typing import List, Tuple, Optional
from pathlib import Path

from packages.shared_types.src.normalized_security_event import NormalizedSecurityEvent
from services.digital_twin.ids.schemas.eve_pipeline_types import (
    MalformedEveRecord, EvePipelineIngestResult
)
from services.digital_twin.ids.suricata.parser.eve_validator import eve_validator
from services.digital_twin.ids.suricata.normalizer.suricata_adapter import suricata_adapter
from services.digital_twin.ids.processor.ids_processor import ids_processor
from services.digital_twin.ids.processor.twin_event_processor import suricata_twin_processor

class SuricataEveCollector:
    """
    Production Suricata EVE telemetry collector.
    Enforces parsing, validation, dead-letter error handling, and normalization.
    """

    def __init__(self):
        self.malformed_queue: List[MalformedEveRecord] = []
        self.normalized_events: List[NormalizedSecurityEvent] = []

    def collect_from_lines(self, lines: List[str]) -> EvePipelineIngestResult:
        result = EvePipelineIngestResult()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            result.totalProcessed += 1

            # 1. JSON Parsing Stage
            try:
                raw_record = json.loads(stripped)
            except json.JSONDecodeError as err:
                malformed = MalformedEveRecord(
                    rawInput=stripped,
                    lineNumber=idx,
                    errorReason=f"Invalid JSON: {str(err)}"
                )
                self.malformed_queue.append(malformed)
                result.malformedRecords.append(malformed)
                result.malformedCount += 1
                continue

            # 2. Structural & Field Validation Stage
            is_valid, validation_err = eve_validator.validate(raw_record)
            if not is_valid:
                malformed = MalformedEveRecord(
                    rawInput=stripped,
                    lineNumber=idx,
                    errorReason=validation_err or "Validation check failed",
                    details=raw_record if isinstance(raw_record, dict) else {}
                )
                self.malformed_queue.append(malformed)
                result.malformedRecords.append(malformed)
                result.malformedCount += 1
                continue

            # 3. Normalization Stage
            try:
                norm_evt = suricata_adapter.normalize(raw_record)
                self.normalized_events.append(norm_evt)
                ids_processor.processed_events.append(norm_evt)
                ids_processor._apply_event_to_twin(norm_evt)
                suricata_twin_processor.processEvent(norm_evt)

                result.validCount += 1
                result.normalizedEventIds.append(norm_evt.eventId)
            except Exception as norm_err:
                malformed = MalformedEveRecord(
                    rawInput=stripped,
                    lineNumber=idx,
                    errorReason=f"Normalization failure: {str(norm_err)}",
                    details=raw_record
                )
                self.malformed_queue.append(malformed)
                result.malformedRecords.append(malformed)
                result.malformedCount += 1

        return result

    def collect_from_string(self, stream_text: str) -> EvePipelineIngestResult:
        return self.collect_from_lines(stream_text.splitlines())

    def collect_from_file(self, file_path: Path) -> EvePipelineIngestResult:
        if not file_path.exists():
            raise FileNotFoundError(f"EVE log file not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            return self.collect_from_lines(f.readlines())

    def clear(self):
        self.malformed_queue.clear()
        self.normalized_events.clear()
        suricata_twin_processor.clear()

suricata_collector = SuricataEveCollector()