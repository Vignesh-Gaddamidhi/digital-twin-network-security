from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

class PatternTypeEnum(str, Enum):
    PERIODIC = "PERIODIC"
    BURST = "BURST"
    REPEATED = "REPEATED"
    SEQUENTIAL = "SEQUENTIAL"
    RANDOMIZED = "RANDOMIZED"
    GRADUAL_INCREASE = "GRADUAL_INCREASE"
    GRADUAL_DECREASE = "GRADUAL_DECREASE"

class ConnectionBehaviourEnum(str, Enum):
    FULL_HANDSHAKE = "FULL_HANDSHAKE"     # SYN -> SYN/ACK -> ACK -> DATA -> FIN
    HALF_OPEN = "HALF_OPEN"               # SYN -> SYN/ACK (no final ACK, SYN flood like)
    RESET_IMMEDIATE = "RESET_IMMEDIATE"   # SYN -> RST (port scan / closed port like)
    CONNECTIONLESS = "CONNECTIONLESS"     # UDP / ICMP raw datagrams
    PERSISTENT_STREAM = "PERSISTENT_STREAM" # Single long-lived connection with periodic data

class PatternTimingConfig(BaseModel):
    startTimeSeconds: float = 0.0
    durationSeconds: float = Field(default=10.0, ge=0.1, le=86400.0)
    rateEventsPerSecond: float = Field(default=5.0, ge=0.1, le=10000.0)
    intervalSeconds: Optional[float] = None
    jitterSeconds: float = Field(default=0.0, ge=0.0, le=10.0)

    @field_validator("intervalSeconds", mode="before")
    @classmethod
    def default_interval(cls, v, info):
        # Default interval to 1.0 / rate if not explicitly supplied
        return v

class GenericTrafficPatternModel(BaseModel):
    patternId: str = Field(default_factory=lambda: f"pat-{uuid.uuid4().hex[:6]}")
    patternType: PatternTypeEnum = PatternTypeEnum.SEQUENTIAL
    protocol: str = "TCP"
    sourceDevice: str = "client-01"
    targetDevice: str = "server-01"
    sourcePortStrategy: str = "EPHEMERAL_RANDOM" # EPHEMERAL_RANDOM or FIXED
    fixedSourcePort: Optional[int] = None
    destinationPorts: List[int] = Field(
        default_factory=lambda: [21, 22, 25, 53, 80, 443, 8080]
    )
    packetSizeBytes: int = Field(default=64, ge=20, le=65535)
    connectionBehaviour: ConnectionBehaviourEnum = ConnectionBehaviourEnum.RESET_IMMEDIATE
    timing: PatternTimingConfig = Field(default_factory=PatternTimingConfig)
    seed: int = 12345
    parameters: Dict[str, Any] = Field(default_factory=dict)

class PatternGenerationResult(BaseModel):
    patternId: str
    patternType: PatternTypeEnum
    protocol: str
    totalPacketsEmitted: int
    totalBytesTransferred: int
    durationSecondsObserved: float
    portsTargeted: List[int]
    firstTimestamp: Optional[str] = None
    lastTimestamp: Optional[str] = None