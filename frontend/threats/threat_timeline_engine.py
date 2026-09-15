from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.threats.threat_models import (
    DetectionSourceEnum, ThreatTimelineItem, ThreatFilterCriteria, UnifiedIncidentDrillDown
)

class ThreatTimelineEngine:
    """Manages timeline event ordering, deduplication, filtering, and unified incident drill-down."""

    def __init__(self):
        self.events: List[ThreatTimelineItem] = []
        self._seed_default_timeline()

    def _seed_default_timeline(self):
        self.events.clear()
        base_events = [
            ThreatTimelineItem(
                eventId="EVT-001-DNS",
                timestamp="2026-09-15T10:01:00Z",
                eventType="DNS_ANOMALY",
                sourceDevice="CLIENT-01",
                destinationDevice="DNS-SERVER-01",
                protocol="UDP",
                destinationPort=53,
                severity=RiskLevelTier.LOW,
                detectionSource=DetectionSourceEnum.ZEEK,
                confidence=0.88,
                riskScore=18.5,
                summary="High volume of unusual NXDOMAIN lookups detected."
            ),
            ThreatTimelineItem(
                eventId="EVT-002-PORT",
                timestamp="2026-09-15T10:04:00Z",
                eventType="PORT_SCAN",
                sourceDevice="ATTACKER-EXT",
                destinationDevice="CLIENT-01",
                protocol="TCP",
                destinationPort=445,
                severity=RiskLevelTier.MEDIUM,
                detectionSource=DetectionSourceEnum.SURICATA,
                confidence=0.92,
                riskScore=38.4,
                summary="Sequential SYN probes across SMB and RPC ports."
            ),
            ThreatTimelineItem(
                eventId="EVT-003-SPIKE",
                timestamp="2026-09-15T10:07:00Z",
                eventType="TRAFFIC_SPIKE",
                sourceDevice="ATTACKER-EXT",
                destinationDevice="WEB-01",
                protocol="TCP",
                destinationPort=443,
                severity=RiskLevelTier.HIGH,
                detectionSource=DetectionSourceEnum.ANOMALY_DETECTOR,
                confidence=0.95,
                riskScore=64.2,
                summary="Volumetric packet surge exceeding 1,800 pkts/sec."
            ),
            ThreatTimelineItem(
                eventId="EVT-004-BEACON",
                timestamp="2026-09-15T10:10:00Z",
                eventType="BEACONING_PATTERN",
                sourceDevice="CLIENT-01",
                destinationDevice="ATTACKER-EXT",
                protocol="HTTPS",
                destinationPort=443,
                severity=RiskLevelTier.HIGH,
                detectionSource=DetectionSourceEnum.TIME_SERIES,
                confidence=0.91,
                riskScore=71.5,
                summary="Fixed-jitter outbound beacon detected over sliding window."
            ),
            ThreatTimelineItem(
                eventId="EVT-005-EXFIL",
                timestamp="2026-09-15T10:14:00Z",
                eventType="EXFILTRATION_LIKE",
                sourceDevice="DB-01",
                destinationDevice="WEB-01",
                protocol="TCP",
                destinationPort=3306,
                severity=RiskLevelTier.CRITICAL,
                detectionSource=DetectionSourceEnum.ML,
                confidence=0.98,
                riskScore=89.6,
                summary="High-volume database payload dump flagged by ensemble model."
            )
        ]
        for e in base_events:
            self.ingest_event(e)

    def ingest_event(self, event: ThreatTimelineItem):
        # 1. Deduplication check: (source, dest, type, timestamp)
        for existing in self.events:
            if (existing.sourceDevice == event.sourceDevice and
                existing.destinationDevice == event.destinationDevice and
                existing.eventType == event.eventType and
                existing.timestamp == event.timestamp):
                return  # Drop duplicate event silently

        self.events.append(event)
        # 2. Chronological ordering
        self.events.sort(key=lambda x: datetime.fromisoformat(x.timestamp.replace("Z", "+00:00")), reverse=True)
        self.events = self.events[:200]

    def get_timeline(self, criteria: Optional[ThreatFilterCriteria] = None) -> List[ThreatTimelineItem]:
        if not criteria:
            return list(self.events)

        filtered = []
        for e in self.events:
            if criteria.severity and e.severity != criteria.severity:
                continue
            if criteria.detectionSource and e.detectionSource != criteria.detectionSource:
                continue
            if criteria.eventType and criteria.eventType.upper() not in e.eventType.upper():
                continue
            if criteria.device and (criteria.device.upper() != e.sourceDevice.upper() and criteria.device.upper() != e.destinationDevice.upper()):
                continue
            if criteria.minRiskScore is not None and e.riskScore < criteria.minRiskScore:
                continue
            if criteria.startTime:
                t_start = datetime.fromisoformat(criteria.startTime.replace("Z", "+00:00"))
                t_event = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
                if t_event < t_start:
                    continue
            if criteria.endTime:
                t_end = datetime.fromisoformat(criteria.endTime.replace("Z", "+00:00"))
                t_event = datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
                if t_event > t_end:
                    continue
            filtered.append(e)
        return filtered

    def get_incident_drilldown(self, event_id: str) -> Optional[UnifiedIncidentDrillDown]:
        target_event = next((e for e in self.events if e.eventId == event_id), None)
        if not target_event:
            return None

        # Build comprehensive unified investigative context
        feats = {
            "packet_rate": 1850.0 if "SPIKE" in target_event.eventType else 240.0,
            "failed_connections": 14.0 if "SCAN" in target_event.eventType else 1.0,
            "destination_diversity": 0.85 if "SCAN" in target_event.eventType else 0.20,
            "flow_duration_variance": 0.05 if "BEACON" in target_event.eventType else 0.45
        }

        det = {
            "detector": target_event.detectionSource.value,
            "signature": f"RULE-{target_event.eventType}-2026",
            "protocol": target_event.protocol,
            "port": target_event.destinationPort,
            "confidence": f"{target_event.confidence * 100:.1f}%"
        }

        risk_ctx = {
            "calculatedScore": target_event.riskScore,
            "assignedLevel": target_event.severity.value,
            "criticalAssetAtRisk": target_event.destinationDevice == "DB-01",
            "mitigationPriority": "IMMEDIATE" if target_event.severity == RiskLevelTier.CRITICAL else "STANDARD"
        }

        pred_attr = {
            "model": "XGBoost-Ensemble-v1",
            "probability": target_event.confidence,
            "topAttributedFeatures": ["connection_frequency", "destination_diversity", "port_entropy"]
        }

        xai_exp = (
            f"Event {target_event.eventType} on {target_event.sourceDevice} was detected by {target_event.detectionSource.value}. "
            f"Phase 15 SHAP highlights an anomaly in connection frequency (+0.31) and destination diversity (+0.24). "
            f"Phase 16 contextual risk engine rates this at {target_event.riskScore:.1f} ({target_event.severity.value}) "
            f"due to reachability toward {target_event.destinationDevice}."
        )

        recom = (
            f"Apply immediate firewall rate-limiting between {target_event.sourceDevice} and {target_event.destinationDevice}."
            if target_event.severity in (RiskLevelTier.HIGH, RiskLevelTier.CRITICAL)
            else "Continue telemetry monitoring and baseline recording."
        )

        return UnifiedIncidentDrillDown(
            event=target_event,
            extractedFeatures=feats,
            detectionDetails=det,
            riskAssessment=risk_ctx,
            predictionAttribution=pred_attr,
            xaiExplanation=xai_exp,
            recommendedContainment=recom
        )

    def render_cli_timeline(self, items: Optional[List[ThreatTimelineItem]] = None) -> str:
        feed = items if items is not None else self.events
        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                          CHRONOLOGICAL THREAT TIMELINE                       ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            "║ TIME     │ EVENT TYPE          │ SOURCE -> DEST      │ DETECTOR   │ SEVERITY ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣"
        ]
        for e in feed[:6]:
            t_short = e.timestamp[11:19]
            flow = f"{e.sourceDevice[:7]}->{e.destinationDevice[:7]}"
            lines.append(f"║ {t_short:<8} │ {e.eventType:<19} │ {flow:<19} │ {e.detectionSource.value:<10} │ {e.severity.value:<8} ║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)

threat_timeline_engine = ThreatTimelineEngine()