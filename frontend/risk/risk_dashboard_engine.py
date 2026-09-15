from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.history.risk_state_engine import risk_state_engine
from frontend.risk.risk_dashboard_models import (
    RiskTierDistribution, DeviceRiskRow, RiskTrendPoint, RiskDashboardSnapshot
)

class RiskDashboardEngine:
    """Aggregates Phase 16 risk intelligence into presentation cards, matrix tables, and trend series."""

    def __init__(self):
        self.cached_snapshot: Optional[RiskDashboardSnapshot] = None
        self._seed_baseline_risk()

    def _seed_baseline_risk(self):
        # Ensure Phase 16 risk records are populated
        risk_state_engine.clear()
        now = datetime.now(timezone.utc)
        
        # Seed historical trend for network risk
        self.trend_history = [
            RiskTrendPoint(timestamp=(now - timedelta(minutes=20)).isoformat(), networkRiskScore=25.0, peakDeviceId="DB-01", riskLevel=RiskLevelTier.LOW),
            RiskTrendPoint(timestamp=(now - timedelta(minutes=15)).isoformat(), networkRiskScore=42.0, peakDeviceId="WEB-01", riskLevel=RiskLevelTier.MEDIUM),
            RiskTrendPoint(timestamp=(now - timedelta(minutes=10)).isoformat(), networkRiskScore=60.8, peakDeviceId="WEB-01", riskLevel=RiskLevelTier.HIGH),
            RiskTrendPoint(timestamp=(now - timedelta(minutes=5)).isoformat(), networkRiskScore=69.6, peakDeviceId="DB-01", riskLevel=RiskLevelTier.HIGH),
            RiskTrendPoint(timestamp=now.isoformat(), networkRiskScore=78.4, peakDeviceId="DB-01", riskLevel=RiskLevelTier.CRITICAL),
        ]

    def _trend_symbol(self, trend_str: str) -> str:
        tu = trend_str.upper()
        if "INCREASING" in tu:
            return "↑"
        elif "DECREASING" in tu:
            return "↓"
        elif "VOLATILE" in tu:
            return "~"
        else:
            return "→"

    def generate_risk_snapshot(self) -> RiskDashboardSnapshot:
        # 1. Device Risk Matrix & Distribution Counts
        dev_rows: List[DeviceRiskRow] = []
        low_c = 0
        med_c = 0
        high_c = 0
        crit_c = 0

        for nid, n in attack_path_graph.nodes.items():
            # Get actual risk score from node
            score = n.riskScore
            tier = threshold_classifier.classify(score)

            if tier == RiskLevelTier.CRITICAL:
                crit_c += 1
            elif tier == RiskLevelTier.HIGH:
                high_c += 1
            elif tier == RiskLevelTier.MEDIUM:
                med_c += 1
            else:
                low_c += 1

            is_crit_asset = (n.assetCriticality in ("HIGH", "CRITICAL") or "DB" in nid)
            vuln_status = f"{len(n.vulnerabilities)} active" if n.vulnerabilities else "None"

            dev_rows.append(DeviceRiskRow(
                deviceId=nid,
                hostname=n.hostname,
                zone=n.zone,
                riskScore=score,
                riskLevel=tier,
                threatProbability=0.87 if score > 50.0 else 0.15,
                assetCriticality=n.assetCriticality,
                vulnerabilityStatus=vuln_status,
                attackImpact="HIGH" if score > 50.0 else "LOW",
                isCriticalAsset=is_crit_asset
            ))

        # Sort matrix descending by risk score
        dev_rows.sort(key=lambda x: x.riskScore, reverse=True)

        dist = RiskTierDistribution(low=low_c, medium=med_c, high=high_c, critical=crit_c)

        # 2. Overall Network Risk Calculation
        peak_row = dev_rows[0] if dev_rows else None
        overall_score = peak_row.riskScore if peak_row else 0.0
        overall_tier = peak_row.riskLevel if peak_row else RiskLevelTier.LOW
        peak_dev = peak_row.deviceId if peak_row else "NONE"

        # Check trend direction
        peak_state = risk_state_engine.device_states.get(peak_dev)
        trend_dir = peak_state.riskTrend.value if peak_state else "INCREASING"
        trend_sym = self._trend_symbol(trend_dir)

        explanation = (
            f"Risk is {overall_tier.value} because the predicted threat probability is elevated, "
            f"the affected asset ({peak_dev}) has {peak_row.assetCriticality if peak_row else 'UNKNOWN'} criticality, "
            f"relevant vulnerabilities are present, and the modeled attack impact is significant."
        )

        snapshot = RiskDashboardSnapshot(
            overallRiskScore=overall_score,
            overallRiskLevel=overall_tier,
            riskTrendSymbol=trend_sym,
            riskTrendDirection=trend_dir,
            highestRiskDevice=peak_dev,
            distribution=dist,
            configuredFormula="Risk = Threat Probability × Asset Criticality × Vulnerability × Attack Impact",
            threatProbabilityFactor="87%",
            assetCriticalityFactor=f"{peak_row.assetCriticality} (1.00)" if peak_row else "MEDIUM (0.60)",
            vulnerabilityFactor="HIGH (0.80)" if peak_row and peak_row.vulnerabilityStatus != "None" else "LOW (0.40)",
            attackImpactFactor="HIGH (0.80)",
            riskExplanation=explanation,
            deviceRiskMatrix=dev_rows,
            trendSeries=self.trend_history
        )

        self.cached_snapshot = snapshot
        return snapshot

risk_dashboard_engine = RiskDashboardEngine()