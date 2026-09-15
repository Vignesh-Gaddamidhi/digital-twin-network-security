from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class TrafficTimeRange(str, Enum):
    RANGE_5M = "5m"
    RANGE_15M = "15m"
    RANGE_30M = "30m"
    RANGE_1H = "1h"
    RANGE_6H = "6h"
    RANGE_24H = "24h"

class TrafficAnomalyType(str, Enum):
    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    PORT_ANOMALY = "PORT_ANOMALY"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    REPEATED_CONNECTION = "REPEATED_CONNECTION"

class TrafficPointDetail(BaseModel):
    pointId: str = Field(default_factory=lambda: f"TP-{uuid.uuid4().hex[:6].upper()}")
    timestamp: str
    sourceDevice: str
    destinationDevice: str
    protocol: str
    port: int
    packets: int
    bytesTransferred: int
    eventType: str = "NORMAL_FLOW"
    anomalyFlag: Optional[TrafficAnomalyType] = None

class ProtocolDistribution(BaseModel):
    tcp: float = 0.0
    udp: float = 0.0
    icmp: float = 0.0
    http: float = 0.0
    https: float = 0.0
    dns: float = 0.0
    ssh: float = 0.0

class TopTalkersSummary(BaseModel):
    topSources: List[Dict[str, Any]] = Field(default_factory=list)
    topDestinations: List[Dict[str, Any]] = Field(default_factory=list)
    topPorts: List[Dict[str, Any]] = Field(default_factory=list)
    topProtocols: List[Dict[str, Any]] = Field(default_factory=list)

class TrafficTimeSeriesPoint(BaseModel):
    timestamp: str
    packetRate: float
    byteRate: float
    connectionsPerSec: float
    activeConnections: int
    hasAnomaly: bool = False
    anomalyType: Optional[TrafficAnomalyType] = None
    sampleDetail: Optional[TrafficPointDetail] = None

class LiveTrafficPanelSnapshot(BaseModel):
    panelId: str = Field(default_factory=lambda: f"TRF-{uuid.uuid4().hex[:6].upper()}")
    timeRange: TrafficTimeRange
    currentPacketRate: float
    currentByteRate: float
    currentConnectionsRate: float
    currentActiveConnections: int
    protocolBreakdown: ProtocolDistribution
    series: List[TrafficTimeSeriesPoint]
    topTalkers: TopTalkersSummary
    anomaliesDetectedCount: int
    lastSampleAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def render_cli_chart(self) -> str:
        if not self.series:
            return "[No Traffic Telemetry Available]"
        rates = [p.packetRate for p in self.series]
        max_r = max(rates) if rates else 1.0
        chart_bars = []
        for p in self.series[-20:]:
            bar_h = int((p.packetRate / max_r) * 8) if max_r > 0 else 0
            marker = "!" if p.hasAnomaly else "█"
            chart_bars.append(marker * max(1, bar_h))

        lines = [
            f"╔══════════════════════════════════════════════════════════════════════════════╗",
            f"║                      TRAFFIC MONITORING PANEL [{self.timeRange.value:<3}]                            ║",
            f"╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ Packets/s: {self.currentPacketRate:6.1f} │ Bytes/s: {self.currentByteRate/1024:5.1f} KB/s │ Active Conns: {self.currentActiveConnections:<3} │ Anomalies: {self.anomaliesDetectedCount:<2} ║",
            f"╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ PROTOCOLS: TCP: {self.protocolBreakdown.tcp:4.1f}% │ HTTPS: {self.protocolBreakdown.https:4.1f}% │ DNS: {self.protocolBreakdown.dns:4.1f}% │ SSH: {self.protocolBreakdown.ssh:4.1f}% ║",
            f"╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ TRAFFIC THROUGHPUT & SPIKE TIMELINE (Last {len(chart_bars)} Samples):                                 ║"
        ]
        # Draw sparkline row
        spark = " ".join([f"[{b}]" for b in chart_bars])
        lines.append(f"║ {spark:<76} ║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)