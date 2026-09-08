from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class NormalTrafficSummaryModel(BaseModel):
    totalEvents: int = 0
    totalPackets: int
    totalBytes: int
    trafficRateBps: float
    tcpCount: int
    udpCount: int
    icmpCount: int
    httpCount: int
    httpsCount: int
    dnsCount: int
    sshCount: int
    activeConnections: int
    averageConnectionsPerDevice: float
    portDistribution: Dict[int, int]
    protocolDistribution: Dict[str, float]
    generatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class BaselineMetadataModel(BaseModel):
    datasetId: str = "normal-baseline-run-001"
    version: str = "1.0.0"
    seed: int = 12345
    durationSeconds: int = 60
    devicesCount: int = 8
    zonesCount: int = 4
    clockTickSeconds: float = 1.0
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hardwareProfile: str = "Enterprise-Branch-Canonical"