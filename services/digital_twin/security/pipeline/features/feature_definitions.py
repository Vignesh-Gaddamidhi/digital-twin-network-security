from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class FeatureWindowEnum(str, Enum):
    WINDOW_5S = "5s"
    WINDOW_30S = "30s"
    WINDOW_60S = "60s"

class SecurityFeatureVector(BaseModel):
    vectorId: str
    targetDevice: str
    sourceDevice: str
    window: FeatureWindowEnum
    windowDurationSeconds: float
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # 1. Volume Dimension
    packetCount: int = 0
    byteCount: int = 0
    packetRate: float = 0.0
    byteRate: float = 0.0

    # 2. Connection Dimension
    connectionCount: int = 0
    failedConnectionCount: int = 0
    successfulConnectionCount: int = 0
    connectionRate: float = 0.0
    failedConnectionRatio: float = 0.0
    averageConnectionDuration: float = 0.0

    # 3. Port Dimension
    destinationPort: Optional[int] = None
    uniqueDestinationPorts: int = 0
    portAttemptCount: int = 0
    failedPortAttempts: int = 0

    # 4. Protocol Dimension
    primaryProtocol: str = "TCP"
    protocolCount: int = 0
    uniqueProtocols: int = 0
    protocolRatioTCP: float = 1.0
    protocolRatioUDP: float = 0.0
    protocolRatioICMP: float = 0.0

    # 5. Timing Dimension
    eventFrequency: float = 0.0
    interArrivalTime: float = 0.0
    averageInterval: float = 0.0
    intervalVariance: float = 0.0

    # 6. Direction Dimension
    inboundBytes: int = 0
    outboundBytes: int = 0
    inboundPackets: int = 0
    outboundPackets: int = 0
    bytesDirectionRatio: float = 1.0  # outbound / (inbound + 1)

    metadata: Dict[str, Any] = Field(default_factory=dict)