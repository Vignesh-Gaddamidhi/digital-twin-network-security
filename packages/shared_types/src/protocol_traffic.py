from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class TransportProtocolEnum(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"

class TrafficDirectionEnum(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    INTERNAL = "INTERNAL"

class SimulatedTcpStateEnum(str, Enum):
    NEW = "NEW"
    CONNECTING = "CONNECTING"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    FAILED = "FAILED"

class IcmpMessageTypeEnum(str, Enum):
    ECHO_REQUEST = "ECHO_REQUEST"
    ECHO_REPLY = "ECHO_REPLY"
    DESTINATION_UNREACHABLE = "DESTINATION_UNREACHABLE"
    TIME_EXCEEDED = "TIME_EXCEEDED"

class UnifiedTrafficEventModel(BaseModel):
    eventId: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:8]}")
    simulationId: str = Field(default="sim-default")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceDevice: str = Field(..., min_length=1)
    destinationDevice: str = Field(..., min_length=1)
    protocol: TransportProtocolEnum
    sourcePort: Optional[int] = Field(default=None, ge=1, le=65535)
    destinationPort: Optional[int] = Field(default=None, ge=1, le=65535)
    bytes: int = Field(default=64, ge=0)
    packets: int = Field(default=1, ge=1)
    direction: TrafficDirectionEnum = TrafficDirectionEnum.OUTBOUND
    tcpState: Optional[SimulatedTcpStateEnum] = None
    icmpType: Optional[IcmpMessageTypeEnum] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("destinationPort")
    @classmethod
    def validate_ports_for_transport(cls, v: Optional[int], info) -> Optional[int]:
        # ICMP typically does not have Layer 4 ports
        proto = info.data.get("protocol")
        if proto in (TransportProtocolEnum.TCP, TransportProtocolEnum.UDP) and v is None:
            raise ValueError(f"Port is required for {proto.value} protocol.")
        return v