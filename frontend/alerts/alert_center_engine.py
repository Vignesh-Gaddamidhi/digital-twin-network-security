import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.threats.threat_models import DetectionSourceEnum
from frontend.alerts.alert_center_models import (
    AlertStatusEnum, SecurityAlertItem, CorrelatedIncidentCampaign,
    AlertFilterCriteria, AlertCounterSummary, EightTierAlertDrillDown
)

class AlertCenterEngine:
    """Manages security alert lifecycle, multi-source correlation, and 8-tier investigative dossiers."""

    def __init__(self):
        self.alerts: List[SecurityAlertItem] = []
        self.campaigns: List[CorrelatedIncidentCampaign] = []
        self._seed_default_alerts()

    def _seed_default_alerts(self):
        self.alerts.clear()
        self.campaigns.clear()

        # Seed realistic alerts
        a1 = SecurityAlertItem(
            alertId="ALT-001",
            timestamp="2026-09-15T10:01:00Z",
            severity=RiskLevelTier.LOW,
            sourceDevice="CLIENT-01",
            destinationDevice="DNS-SERVER-01",
            eventType="DNS_ANOMALY",
            detectionSource=DetectionSourceEnum.ZEEK,
            confidence=0.88,
            riskScore=18.5,
            status=AlertStatusEnum.NEW,
            summary="Anomalous NXDOMAIN rate spike from workstation"
        )
        a2 = SecurityAlertItem(
            alertId="ALT-002",
            timestamp="2026-09-15T10:04:00Z",
            severity=RiskLevelTier.MEDIUM,
            sourceDevice="CLIENT-01",
            destinationDevice="WEB-01",
            eventType="PORT_SCAN",
            detectionSource=DetectionSourceEnum.SURICATA,
            confidence=0.92,
            riskScore=38.4,
            status=AlertStatusEnum.INVESTIGATING,
            summary="Lateral probe across TCP port 22 and port 80"
        )
        a3 = SecurityAlertItem(
            alertId="ALT-003",
            timestamp="2026-09-15T10:07:00Z",
            severity=RiskLevelTier.HIGH,
            sourceDevice="ATTACKER-EXT",
            destinationDevice="WEB-01",
            eventType="TRAFFIC_SPIKE",
            detectionSource=DetectionSourceEnum.ANOMALY_DETECTOR,
            confidence=0.95,
            riskScore=64.2,
            status=AlertStatusEnum.ACKNOWLEDGED,
            summary="Inbound connection frequency surge exceeding 1,800 pkts/s"
        )
        a4 = SecurityAlertItem(
            alertId="ALT-004",
            timestamp="2026-09-15T10:14:00Z",
            severity=RiskLevelTier.CRITICAL,
            sourceDevice="DB-01",
            destinationDevice="WEB-01",
            eventType="EXFILTRATION_LIKE",
            detectionSource=DetectionSourceEnum.ML,
            confidence=0.98,
            riskScore=89.6,
            status=AlertStatusEnum.NEW,
            summary="High-volume database extraction matching exfiltration heuristics"
        )

        for a in [a1, a2, a3, a4]:
            self.create_alert(a)

        # Correlate a1, a2, a4 into a unified campaign
        self.correlate_incident_campaign(
            campaign_name="Targeted Lateral Database Infiltration",
            alert_ids=["ALT-001", "ALT-002", "ALT-004"],
            root_cause="LATERAL_MOVEMENT_LIKE"
        )

    def create_alert(self, alert: SecurityAlertItem) -> SecurityAlertItem:
        # Deduplication check
        for existing in self.alerts:
            if (existing.sourceDevice == alert.sourceDevice and
                existing.destinationDevice == alert.destinationDevice and
                existing.eventType == alert.eventType and
                existing.timestamp == alert.timestamp):
                return existing  # Suppress duplicate

        self.alerts.append(alert)
        self.alerts.sort(key=lambda x: datetime.fromisoformat(x.timestamp.replace("Z", "+00:00")), reverse=True)
        return alert

    def update_alert_status(self, alert_id: str, new_status: AlertStatusEnum) -> SecurityAlertItem:
        for a in self.alerts:
            if a.alertId == alert_id:
                a.status = new_status
                return a
        raise KeyError(f"ALERT_NOT_FOUND: Alert '{alert_id}' does not exist.")

    def correlate_incident_campaign(
        self,
        campaign_name: str,
        alert_ids: List[str],
        root_cause: str = "MULTI_STAGE_ATTACK"
    ) -> CorrelatedIncidentCampaign:
        matched_alerts = [a for a in self.alerts if a.alertId in alert_ids]
        if not matched_alerts:
            raise ValueError("No matching alerts found to correlate into campaign.")

        devs = set()
        scores = []
        for a in matched_alerts:
            devs.add(a.sourceDevice)
            devs.add(a.destinationDevice)
            scores.append(a.riskScore)

        # Assign campaign ID back to alerts
        camp_id = f"CAMP-{uuid.uuid4().hex[:6].upper()}"
        for a in matched_alerts:
            a.correlatedCampaignId = camp_id

        camp = CorrelatedIncidentCampaign(
            campaignId=camp_id,
            campaignName=campaign_name,
            involvedAlertIds=[a.alertId for a in matched_alerts],
            participatingDevices=list(devs),
            rootCauseCategory=root_cause,
            maxSeverity=RiskLevelTier.CRITICAL if any(a.severity == RiskLevelTier.CRITICAL for a in matched_alerts) else RiskLevelTier.HIGH,
            aggregateRiskScore=max(scores),
            timelineSpan=f"{matched_alerts[-1].timestamp[11:16]} - {matched_alerts[0].timestamp[11:16]} UTC",
            narrative=(
                f"Automated correlation fused {len(matched_alerts)} related security alerts spanning "
                f"{len(devs)} hosts ({', '.join(devs)}). Primary vector: {root_cause} targeting database assets."
            )
        )
        self.campaigns.append(camp)
        return camp

    def filter_alerts(self, criteria: Optional[AlertFilterCriteria] = None) -> List[SecurityAlertItem]:
        if not criteria:
            return list(self.alerts)

        res = []
        for a in self.alerts:
            if criteria.severity and a.severity != criteria.severity:
                continue
            if criteria.status and a.status != criteria.status:
                continue
            if criteria.device and (a.sourceDevice.upper() != criteria.device.upper() and a.destinationDevice.upper() != criteria.device.upper()):
                continue
            if criteria.detectionSource and a.detectionSource != criteria.detectionSource:
                continue
            if criteria.eventType and criteria.eventType.upper() not in a.eventType.upper():
                continue
            if criteria.minRiskScore is not None and a.riskScore < criteria.minRiskScore:
                continue
            res.append(a)
        return res

    def get_alert_counters(self) -> AlertCounterSummary:
        new_c = sum(1 for a in self.alerts if a.status == AlertStatusEnum.NEW)
        inv_c = sum(1 for a in self.alerts if a.status == AlertStatusEnum.INVESTIGATING)
        high_c = sum(1 for a in self.alerts if a.severity == RiskLevelTier.HIGH)
        crit_c = sum(1 for a in self.alerts if a.severity == RiskLevelTier.CRITICAL)
        return AlertCounterSummary(
            newAlerts=new_c,
            investigatingAlerts=inv_c,
            highSeverityAlerts=high_c,
            criticalSeverityAlerts=crit_c,
            totalActive=len(self.alerts)
        )

    def get_8tier_drilldown(self, alert_id: str) -> EightTierAlertDrillDown:
        target_alert = next((a for a in self.alerts if a.alertId == alert_id), None)
        if not target_alert:
            raise KeyError(f"ALERT_NOT_FOUND: Alert '{alert_id}' does not exist.")

        return EightTierAlertDrillDown(
            alert=target_alert,
            eventContext={
                "rawEventId": f"EVT-RAW-{target_alert.alertId}",
                "timestamp": target_alert.timestamp,
                "protocol": "TCP",
                "trafficRate": "240 pkts/s"
            },
            featureVector={
                "connection_frequency": 145.0,
                "destination_diversity": 0.88,
                "port_entropy": 0.92,
                "byte_rate": 89600.0
            },
            detectionDetails={
                "source": target_alert.detectionSource.value,
                "confidenceScore": f"{target_alert.confidence*100:.1f}%",
                "matchedSignature": f"RULE-{target_alert.eventType}-2026"
            },
            mlPrediction={
                "model": "RandomForest-v1.2",
                "predictedCategory": target_alert.eventType,
                "probability": target_alert.confidence
            },
            xaiAttribution={
                "primaryFactor": "connection_frequency (+0.31)",
                "secondaryFactor": "destination_diversity (+0.22)",
                "narrative": "Anomaly driven by abnormal connection burst and port diversification."
            },
            riskBreakdown={
                "threatProbability": target_alert.confidence,
                "assetCriticality": "CRITICAL (1.00)" if target_alert.destinationDevice == "DB-01" else "HIGH (0.80)",
                "vulnerabilityFactor": 0.80,
                "attackImpact": 0.80,
                "compositeRisk": target_alert.riskScore
            },
            attackPathTrajectory={
                "traversedRoute": [target_alert.sourceDevice, "WEB-01", target_alert.destinationDevice],
                "pathLength": 2,
                "reachability": "REACHABLE",
                "targetCrownJewel": target_alert.destinationDevice
            },
            affectedDeviceSummary={
                "deviceId": target_alert.destinationDevice,
                "zone": "DATABASE" if "DB" in target_alert.destinationDevice else "DMZ",
                "isolationStatus": False,
                "mitigationPlaybook": "ENFORCE_PORT_ISOLATION_ACL"
            }
        )

    def render_cli_alert_table(self, alert_list: Optional[List[SecurityAlertItem]] = None) -> str:
        feed = alert_list if alert_list is not None else self.alerts
        counters = self.get_alert_counters()
        lines = [
            "â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—",
            "â•‘                        SECURITY OPERATIONS ALERT CENTER                      â•‘",
            f"â•‘ Active: {counters.totalActive:02d} â”‚ NEW: {counters.newAlerts:02d} â”‚ INVESTIGATING: {counters.investigatingAlerts:02d} â”‚ HIGH: {counters.highSeverityAlerts:02d} â”‚ CRITICAL: {counters.criticalSeverityAlerts:02d} â•‘",
            "â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£",
            "â•‘ ID      â”‚ TIME     â”‚ SEVERITY â”‚ SOURCE -> DEST      â”‚ EVENT TYPE       â”‚ STATUS    â•‘",
            "â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£"
        ]
        for a in feed[:6]:
            t_short = a.timestamp[11:19]
            flow = f"{a.sourceDevice[:7]}->{a.destinationDevice[:7]}"
            lines.append(f"â•‘ {a.alertId:<7} â”‚ {t_short:<8} â”‚ {a.severity.value:<8} â”‚ {flow:<19} â”‚ {a.eventType:<16} â”‚ {a.status.value:<9} â•‘")
        lines.append("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•")
        return "\n".join(lines)

alert_center_engine = AlertCenterEngine()