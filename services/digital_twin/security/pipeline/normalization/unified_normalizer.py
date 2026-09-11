from typing import Dict, Any, Optional, List, Tuple
from services.digital_twin.security.pipeline.normalization.canonical_event import (
    CanonicalEvent, QuarantinedEventRecord
)
from services.digital_twin.security.pipeline.normalization.source_normalizers import (
    suricata_normalizer, zeek_normalizer, simulation_normalizer, NormalizationError
)

class UnifiedEventNormalizer:
    """Master Multi-Source Event Normalization Engine with Quarantine and Schema Alignment."""

    def __init__(self):
        self.quarantine_store: List[QuarantinedEventRecord] = []
        self.normalized_store: List[CanonicalEvent] = []

    def normalize(self, raw_record: Dict[str, Any], source_type: Optional[str] = None) -> Tuple[Optional[CanonicalEvent], Optional[str]]:
        if not isinstance(raw_record, dict):
            reason = "Malformed payload: Input is not a JSON dictionary"
            self._quarantine(raw_record, reason, str(source_type or "UNKNOWN"))
            return None, reason

        inferred_src = (source_type or "").upper()
        if not inferred_src:
            if "alert" in raw_record or raw_record.get("event_type") in ("alert", "flow", "http", "tls"):
                inferred_src = "SURICATA"
            elif "id.orig_h" in raw_record or "conn_state" in raw_record or "ts" in raw_record:
                inferred_src = "ZEEK"
            elif "simulationId" in raw_record or "sourceDevice" in raw_record:
                inferred_src = "SIMULATION"
            else:
                inferred_src = "SURICATA"

        try:
            if inferred_src == "SURICATA":
                event = suricata_normalizer.normalize(raw_record)
            elif inferred_src == "ZEEK":
                event = zeek_normalizer.normalize(raw_record)
            elif inferred_src == "SIMULATION":
                event = simulation_normalizer.normalize(raw_record)
            else:
                raise NormalizationError(f"Unknown detection source '{inferred_src}'")

            self.normalized_store.append(event)
            return event, None

        except NormalizationError as ne:
            err_msg = str(ne)
            self._quarantine(raw_record, err_msg, inferred_src)
            return None, err_msg
        except Exception as ex:
            err_msg = f"Unexpected normalization crash: {str(ex)}"
            self._quarantine(raw_record, err_msg, inferred_src)
            return None, err_msg

    def _quarantine(self, raw_input: Any, reason: str, src: str):
        record = QuarantinedEventRecord(
            rawInput=raw_input,
            rejectionReason=reason,
            attemptedSource=src
        )
        self.quarantine_store.append(record)

    def clear(self):
        self.quarantine_store.clear()
        self.normalized_store.clear()

unified_normalizer = UnifiedEventNormalizer()