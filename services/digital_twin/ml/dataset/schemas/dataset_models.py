from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class BinaryLabelEnum(str, Enum):
    NORMAL = "NORMAL"
    ANOMALOUS = "ANOMALOUS"

class MulticlassLabelEnum(str, Enum):
    NORMAL = "NORMAL"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    DOS = "DOS"
    DNS_ANOMALY = "DNS_ANOMALY"
    BEACONING = "BEACONING"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"

class TelemetrySourceTypeEnum(str, Enum):
    SIMULATION_TRAFFIC = "SIMULATION_TRAFFIC"
    ATTACK_SCENARIO = "ATTACK_SCENARIO"
    SURICATA_IDS = "SURICATA_IDS"
    ZEEK_NSM = "ZEEK_NSM"
    PIPELINE_CANONICAL = "PIPELINE_CANONICAL"

class DatasetSample(BaseModel):
    # --- Identifiers & Auditing (Excluded from training features) ---
    sampleId: str = Field(default_factory=lambda: f"SMP-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceDevice: str
    destinationDevice: str
    telemetrySource: TelemetrySourceTypeEnum

    # --- Categorical Features ---
    protocol: str = "TCP"
    destinationPort: int = 80
    service: Optional[str] = "HTTP"
    direction: str = "OUTBOUND"  # INBOUND | OUTBOUND | INTERNAL

    # --- Numerical Features (Volume, Timing, Ratios) ---
    bytes: int = 0
    packets: int = 1
    flowDuration: float = 0.0
    packetRate: float = 0.0
    byteRate: float = 0.0
    connectionFrequency: float = 0.0
    failedConnections: int = 0
    uniquePorts: int = 1
    destinationDiversity: float = 1.0
    dnsFrequency: float = 0.0
    interArrivalTime: float = 0.0
    intervalVariance: float = 0.0
    bytesDirectionRatio: float = 1.0

    # --- Ground Truth Targets ---
    binaryLabel: BinaryLabelEnum = BinaryLabelEnum.NORMAL
    multiclassLabel: MulticlassLabelEnum = MulticlassLabelEnum.NORMAL

    # --- Lineage ---
    scenarioId: Optional[str] = None
    originalEventId: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_feature_dict(self) -> Dict[str, Any]:
        """Extracts numerical and categorical features suitable for ML models."""
        return {
            "protocol": self.protocol,
            "destinationPort": self.destinationPort,
            "service": self.service,
            "direction": self.direction,
            "bytes": self.bytes,
            "packets": self.packets,
            "flowDuration": self.flowDuration,
            "packetRate": self.packetRate,
            "byteRate": self.byteRate,
            "connectionFrequency": self.connectionFrequency,
            "failedConnections": self.failedConnections,
            "uniquePorts": self.uniquePorts,
            "destinationDiversity": self.destinationDiversity,
            "dnsFrequency": self.dnsFrequency,
            "interArrivalTime": self.interArrivalTime,
            "intervalVariance": self.intervalVariance,
            "bytesDirectionRatio": self.bytesDirectionRatio
        }

class DatasetMetadata(BaseModel):
    datasetId: str = Field(default_factory=lambda: f"DS-{uuid.uuid4().hex[:8].upper()}")
    version: str = "1.0.0"
    creationTime: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sourceTypes: List[TelemetrySourceTypeEnum] = Field(default_factory=list)
    featureVersion: str = "feat-v1"
    labelingVersion: str = "lbl-v1"
    splitVersion: Optional[str] = None
    totalSamples: int = 0
    normalSamples: int = 0
    anomalousSamples: int = 0
    multiclassCounts: Dict[str, int] = Field(default_factory=dict)
    description: str = "Phase 11 ML Dataset synthesized from Digital Twin telemetry"
    metadata: Dict[str, Any] = Field(default_factory=dict)