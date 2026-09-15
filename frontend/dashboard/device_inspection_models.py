from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class EpistemicProvenanceEnum(str, Enum):
    REAL_TELEMETRY = "REAL_TELEMETRY"
    SIMULATION = "SIMULATION"
    PREDICTED = "PREDICTED"

class DeviceResourceUtilization(BaseModel):
    cpuPercent: float = 0.0
    memoryPercent: float = 0.0
    networkUtilizationPercent: float = 0.0
    packetRatePerSec: float = 0.0
    byteRatePerSec: float = 0.0
    activeConnectionCount: int = 0

class DeviceStateTimelineItem(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str
    riskScore: float
    triggerEvent: Optional[str] = None

class LiveDeviceDetailView(BaseModel):
    deviceId: str
    hostname: str
    deviceType: str
    zone: str
    ipAddresses: List[str]
    macAddress: str
    os: str
    
    # Provenance separation
    provenance: EpistemicProvenanceEnum = EpistemicProvenanceEnum.SIMULATION
    
    # Live Vitals
    utilization: DeviceResourceUtilization = Field(default_factory=DeviceResourceUtilization)
    
    # Security State
    securityStatus: str = "NORMAL"
    riskScore: float = 0.0
    riskLevel: RiskLevelTier = RiskLevelTier.LOW
    confidenceScore: float = 0.95
    activeAlertsCount: int = 0
    vulnerabilitiesCount: int = 0
    activeVulnerabilities: List[str] = Field(default_factory=list)
    openPorts: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    lastSecurityEvent: Optional[str] = None
    
    # State History
    stateHistory: List[DeviceStateTimelineItem] = Field(default_factory=list)
    lastTelemetryUpdate: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_formatted_cli_panel(self) -> str:
        u = self.utilization
        ports_str = ", ".join(str(p) for p in self.openPorts) if self.openPorts else "None"
        srv_str = ", ".join(self.services) if self.services else "None"
        hist_str = " -> ".join([h.status for h in self.stateHistory[-4:]]) if self.stateHistory else self.securityStatus
        return (
            f"┌─────────────────────────────────────────────────────────────┐\n"
            f"│ DEVICE INSPECTOR: {self.deviceId:<18} [{self.zone:<8}]           │\n"
            f"├─────────────────────────────────────────────────────────────┤\n"
            f"│ Hostname    : {self.hostname:<41} │\n"
            f"│ Type / OS   : {self.deviceType:<20} │ {self.os:<18} │\n"
            f"│ IP / MAC    : {self.ipAddresses[0]:<15} │ {self.macAddress:<17} │\n"
            f"│ Provenance  : [{self.provenance.value:<15}]                           │\n"
            f"├─────────────────────────────────────────────────────────────┤\n"
            f"│ CPU         : {u.cpuPercent:4.1f}%     Memory       : {u.memoryPercent:4.1f}%            │\n"
            f"│ Network     : {u.networkUtilizationPercent:4.1f}%     Active Conns : {u.activeConnectionCount:<6}            │\n"
            f"│ Packets/sec : {u.packetRatePerSec:<8.1f} Bytes/sec    : {u.byteRatePerSec/1024:<5.1f} KB/s         │\n"
            f"├─────────────────────────────────────────────────────────────┤\n"
            f"│ Open Ports  : {ports_str:<41} │\n"
            f"│ Services    : {srv_str:<41} │\n"
            f"│ Risk        : {self.riskScore:4.1f} / 100.0 [{self.riskLevel.value:<8}] (Conf: {self.confidenceScore*100:.0f}%)   │\n"
            f"│ Alerts      : {self.activeAlertsCount:<2}           Vulnerabilities: {self.vulnerabilitiesCount:<2}            │\n"
            f"│ State Hist  : {hist_str:<41} │\n"
            f"└─────────────────────────────────────────────────────────────┘"
        )

class DeviceSearchQuery(BaseModel):
    query: str = ""
    zone: Optional[str] = None
    securityStatus: Optional[str] = None
    minRiskScore: Optional[float] = None