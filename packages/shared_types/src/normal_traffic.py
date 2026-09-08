from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class NormalProtocolWeightEnum(str, Enum):
    HTTPS = "HTTPS"
    DNS = "DNS"
    HTTP = "HTTP"
    SSH = "SSH"
    ICMP = "ICMP"
    TCP = "TCP"
    UDP = "UDP"

class NormalTrafficScenarioConfig(BaseModel):
    scenarioId: str = Field(default="normal-baseline-run-001", min_length=2)
    name: str = "Enterprise Normal Baseline Profile"
    durationSeconds: int = Field(default=60, ge=1, le=86400)
    seed: int = Field(default=12345)
    tickStepSeconds: float = Field(default=1.0, ge=0.1, le=10.0)
    protocolWeights: Dict[NormalProtocolWeightEnum, float] = Field(
        default_factory=lambda: {
            NormalProtocolWeightEnum.HTTPS: 0.35,
            NormalProtocolWeightEnum.DNS: 0.30,
            NormalProtocolWeightEnum.HTTP: 0.15,
            NormalProtocolWeightEnum.SSH: 0.08,
            NormalProtocolWeightEnum.ICMP: 0.07,
            NormalProtocolWeightEnum.TCP: 0.03,
            NormalProtocolWeightEnum.UDP: 0.02
        }
    )
    clientDevices: List[str] = Field(default_factory=lambda: ["client-01", "admin-01"])
    webServers: List[str] = Field(default_factory=lambda: ["web-01"])
    dnsServers: List[str] = Field(default_factory=lambda: ["dns-01"])
    genericServers: List[str] = Field(default_factory=lambda: ["server-01", "db-01"])

class BaselineSummaryModel(BaseModel):
    baselineId: str
    scenarioName: str
    seed: int
    durationSeconds: int
    totalEventsCount: int
    totalBytesTransferred: int
    totalPacketsTransferred: int
    protocolDistribution: Dict[str, int]
    portDistribution: Dict[int, int]
    destinationDistribution: Dict[str, int]
    generatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class OrchestratorEventEnvelope(BaseModel):
    envelopeId: str = Field(default_factory=lambda: f"env-{uuid.uuid4().hex[:8]}")
    simTimeSeconds: float
    protocol: str
    sourceDevice: str
    destinationDevice: str
    destinationPort: Optional[int] = None
    bytes: int
    packets: int = 1
    summary: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())