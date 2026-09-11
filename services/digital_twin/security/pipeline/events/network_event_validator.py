from typing import Tuple, Optional
from services.digital_twin.security.pipeline.events.network_event import (
    NetworkEvent, NetworkEventTypeEnum, DetectionSourceEnum
)

class NetworkEventValidationError(Exception):
    pass

class NetworkEventValidator:
    """Validates that a NetworkEvent satisfies all canonical structural invariants."""

    @staticmethod
    def validate(event: NetworkEvent) -> Tuple[bool, Optional[str]]:
        if not event.eventId or not event.eventId.strip():
            return False, "Missing mandatory field 'eventId'"

        if not event.timestamp or not event.timestamp.strip():
            return False, "Missing mandatory field 'timestamp'"

        if not event.source or not event.source.strip():
            return False, "Missing mandatory field 'source' (source device/IP)"

        if not event.destination or not event.destination.strip():
            return False, "Missing mandatory field 'destination' (destination device/IP)"

        if not event.protocol or not event.protocol.strip():
            return False, "Missing mandatory field 'protocol'"

        if event.destinationPort is not None:
            if not (0 <= event.destinationPort <= 65535):
                return False, f"Invalid destinationPort: {event.destinationPort} (out of range 0-65535)"

        if event.sourcePort is not None:
            if not (0 <= event.sourcePort <= 65535):
                return False, f"Invalid sourcePort: {event.sourcePort} (out of range 0-65535)"

        if not isinstance(event.eventType, NetworkEventTypeEnum):
            return False, f"Invalid eventType '{event.eventType}'"

        if not isinstance(event.detectionSource, DetectionSourceEnum):
            return False, f"Invalid detectionSource '{event.detectionSource}'"

        return True, None

    @classmethod
    def assert_valid(cls, event: NetworkEvent):
        valid, reason = cls.validate(event)
        if not valid:
            raise NetworkEventValidationError(reason)

network_event_validator = NetworkEventValidator()