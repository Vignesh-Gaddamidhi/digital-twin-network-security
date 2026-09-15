from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
import math

from frontend.traffic.traffic_models import (
    TrafficTimeRange, TrafficAnomalyType, TrafficPointDetail, ProtocolDistribution,
    TopTalkersSummary, TrafficTimeSeriesPoint, LiveTrafficPanelSnapshot
)

class TrafficMonitoringEngine:
    """Aggregates and formats live network traffic, protocol breakdown, and anomaly detection."""

    def __init__(self):
        self.raw_samples: List[TrafficPointDetail] = []
        self._seed_baseline_traffic()

    def _seed_baseline_traffic(self):
        now = datetime.now(timezone.utc)
        self.raw_samples.clear()

        # Seed 30 synthetic data points across the past 30 minutes
        nodes = ["CLIENT-01", "WEB-01", "DB-01", "DNS-SERVER-01", "ATTACKER-EXT"]
        for i in range(30):
            ts = (now - timedelta(minutes=30 - i)).isoformat()
            is_spike = (i == 24 or i == 25)
            pkts = 1850 if is_spike else (120 + (i * 12))
            bytes_t = pkts * 850
            src = "ATTACKER-EXT" if is_spike else nodes[i % len(nodes)]
            dst = "WEB-01" if is_spike else nodes[(i + 1) % len(nodes)]
            port = 443 if is_spike else (80 if i % 2 == 0 else 53)
            proto = "TCP" if port in (80, 443) else "UDP"

            anomaly = TrafficAnomalyType.TRAFFIC_SPIKE if is_spike else None

            self.raw_samples.append(TrafficPointDetail(
                pointId=f"TP-{i:03d}",
                timestamp=ts,
                sourceDevice=src,
                destinationDevice=dst,
                protocol=proto,
                port=port,
                packets=pkts,
                bytesTransferred=bytes_t,
                eventType="DOS_SATURATION" if is_spike else "NORMAL_TELEMETRY",
                anomalyFlag=anomaly
            ))

    def ingest_traffic_sample(self, sample: TrafficPointDetail):
        self.raw_samples.append(sample)
        # Keep sliding memory bounded
        self.raw_samples = self.raw_samples[-500:]

    def _filter_samples_by_range(self, time_range: TrafficTimeRange) -> List[TrafficPointDetail]:
        range_deltas = {
            TrafficTimeRange.RANGE_5M: timedelta(minutes=5),
            TrafficTimeRange.RANGE_15M: timedelta(minutes=15),
            TrafficTimeRange.RANGE_30M: timedelta(minutes=30),
            TrafficTimeRange.RANGE_1H: timedelta(hours=1),
            TrafficTimeRange.RANGE_6H: timedelta(hours=6),
            TrafficTimeRange.RANGE_24H: timedelta(hours=24),
        }
        max_delta = range_deltas.get(time_range, timedelta(minutes=30))
        cutoff = datetime.now(timezone.utc) - max_delta

        filtered = []
        for s in self.raw_samples:
            try:
                t = datetime.fromisoformat(s.timestamp)
                if t >= cutoff:
                    filtered.append(s)
            except Exception:
                filtered.append(s)
        return filtered

    def generate_traffic_snapshot(self, time_range: TrafficTimeRange = TrafficTimeRange.RANGE_30M) -> LiveTrafficPanelSnapshot:
        samples = self._filter_samples_by_range(time_range)

        if not samples:
            # Zero state
            return LiveTrafficPanelSnapshot(
                timeRange=time_range,
                currentPacketRate=0.0,
                currentByteRate=0.0,
                currentConnectionsRate=0.0,
                currentActiveConnections=0,
                protocolBreakdown=ProtocolDistribution(),
                series=[],
                topTalkers=TopTalkersSummary(),
                anomaliesDetectedCount=0
            )

        # 1. Build Time Series
        series: List[TrafficTimeSeriesPoint] = []
        proto_counts: Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0, "HTTPS": 0, "DNS": 0, "SSH": 0}
        src_counts: Dict[str, int] = {}
        dst_counts: Dict[str, int] = {}
        port_counts: Dict[int, int] = {}

        for s in samples:
            has_ano = s.anomalyFlag is not None
            pkt_rate = float(s.packets)
            byte_rate = float(s.bytesTransferred)

            series.append(TrafficTimeSeriesPoint(
                timestamp=s.timestamp,
                packetRate=pkt_rate,
                byteRate=byte_rate,
                connectionsPerSec=round(pkt_rate / 25.0, 1),
                activeConnections=max(1, int(pkt_rate / 40.0)),
                hasAnomaly=has_ano,
                anomalyType=s.anomalyFlag,
                sampleDetail=s
            ))

            # Protocol attribution
            proto_upper = s.protocol.upper()
            if s.port == 443:
                proto_counts["HTTPS"] += s.packets
            elif s.port == 80:
                proto_counts["HTTP"] += s.packets
            elif s.port == 53:
                proto_counts["DNS"] += s.packets
            elif s.port == 22:
                proto_counts["SSH"] += s.packets
            elif proto_upper in proto_counts:
                proto_counts[proto_upper] += s.packets
            else:
                proto_counts["TCP"] += s.packets

            src_counts[s.sourceDevice] = src_counts.get(s.sourceDevice, 0) + s.packets
            dst_counts[s.destinationDevice] = dst_counts.get(s.destinationDevice, 0) + s.packets
            port_counts[s.port] = port_counts.get(s.port, 0) + s.packets

        # 2. Protocol Breakdown
        total_p = sum(proto_counts.values()) or 1
        p_dist = ProtocolDistribution(
            tcp=round((proto_counts["TCP"] / total_p) * 100.0, 1),
            udp=round((proto_counts["UDP"] / total_p) * 100.0, 1),
            icmp=round((proto_counts["ICMP"] / total_p) * 100.0, 1),
            http=round((proto_counts["HTTP"] / total_p) * 100.0, 1),
            https=round((proto_counts["HTTPS"] / total_p) * 100.0, 1),
            dns=round((proto_counts["DNS"] / total_p) * 100.0, 1),
            ssh=round((proto_counts["SSH"] / total_p) * 100.0, 1),
        )

        # 3. Top Talkers
        top_talkers = TopTalkersSummary(
            topSources=[{"device": k, "packets": v} for k, v in sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:4]],
            topDestinations=[{"device": k, "packets": v} for k, v in sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:4]],
            topPorts=[{"port": k, "packets": v} for k, v in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:4]],
            topProtocols=[{"protocol": k, "percentage": v} for k, v in p_dist.model_dump().items() if v > 0.0]
        )

        latest = series[-1]
        anomalies_count = sum(1 for pt in series if pt.hasAnomaly)

        return LiveTrafficPanelSnapshot(
            timeRange=time_range,
            currentPacketRate=latest.packetRate,
            currentByteRate=latest.byteRate,
            currentConnectionsRate=latest.connectionsPerSec,
            currentActiveConnections=latest.activeConnections,
            protocolBreakdown=p_dist,
            series=series,
            topTalkers=top_talkers,
            anomaliesDetectedCount=anomalies_count
        )

    def drill_down_point(self, point_id: str) -> Optional[TrafficPointDetail]:
        for s in self.raw_samples:
            if s.pointId == point_id:
                return s
        return None

traffic_monitoring_engine = TrafficMonitoringEngine()