import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
import shap

ROOT_DIR = Path(__file__).resolve().parents[5]
REPORTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "xai" / "reports"
XAI_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai"

from services.digital_twin.ml.xai.shap.shap_models import FeatureSHAPItem, ContributionDirection, SHAPExplanation
from services.digital_twin.ml.xai.visualization.dashboard_models import (
    EvidenceSeverityLevel, ObservedEvidenceItem, WhyContributionItem,
    PredictionExplanationCardData, XAIAuditTrail, ComprehensiveXAIForensicReport
)
from services.digital_twin.ml.xai.feature_importance.global_importance_engine import global_feature_importance_engine

class XAIDashboardEngine:
    """Generates visual dashboard components, evidence panels, audit hashes, and forensic reports."""

    FEATURE_UNITS = {
        "packet_rate": "pkts/s",
        "bytes": "bytes",
        "bytes_per_second": "B/s",
        "connection_frequency": "conns/s",
        "unique_destination_ports": "ports",
        "failed_connections": "failures",
        "dns_frequency": "queries/s",
        "destination_diversity": "ratio",
        "flow_duration": "seconds"
    }

    def __init__(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        XAI_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_input_hash(features: Dict[str, float], model_version: str, feature_version: str) -> str:
        canonical_str = json.dumps(features, sort_keys=True) + f"|{model_version}|{feature_version}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def build_evidence_panel(self, feature_values: Dict[str, float]) -> List[ObservedEvidenceItem]:
        items = []
        for fn, val in feature_values.items():
            flabel = fn.replace("_", " ").capitalize()
            unit = self.FEATURE_UNITS.get(fn, "units")

            # Determine qualitative operational rating based on telemetry deviation
            if val >= 3.0:
                sev = EvidenceSeverityLevel.HIGH
                note = f"Observed {val:.2f} significantly above baseline tolerances"
            elif val >= 1.5:
                sev = EvidenceSeverityLevel.ELEVATED
                note = f"Observed {val:.2f} moderately higher than expected"
            elif val >= 0.5:
                sev = EvidenceSeverityLevel.MODERATELY_ELEVATED
                note = f"Observed {val:.2f} slightly elevated"
            else:
                sev = EvidenceSeverityLevel.NORMAL
                note = f"Observed {val:.2f} conforms to learned baseline"

            items.append(ObservedEvidenceItem(
                featureName=fn,
                featureLabel=flabel,
                observedValue=round(float(val), 2),
                unit=unit,
                severity=sev,
                contextNote=note
            ))

        items.sort(key=lambda x: x.observedValue, reverse=True)
        return items

    def build_why_panel(self, shap_items: List[FeatureSHAPItem]) -> List[WhyContributionItem]:
        items = []
        for it in shap_items:
            flabel = it.featureName.replace("_", " ").capitalize()
            if it.direction == ContributionDirection.POSITIVE:
                indicator = "↑"
                direction_str = "POSITIVE"
                if abs(it.shapValue) >= 0.20:
                    desc = "Strong positive contribution"
                elif abs(it.shapValue) >= 0.10:
                    desc = "Positive contribution"
                else:
                    desc = "Moderate positive contribution"
            else:
                indicator = "↓"
                direction_str = "NEGATIVE"
                if abs(it.shapValue) >= 0.10:
                    desc = "Moderate negative contribution"
                else:
                    desc = "Slight negative contribution"

            items.append(WhyContributionItem(
                featureName=it.featureName,
                featureLabel=flabel,
                directionIndicator=indicator,
                direction=direction_str,
                shapValue=it.shapValue,
                shapFormatted=it.shapValueFormatted,
                impactDescription=desc
            ))

        items.sort(key=lambda x: abs(x.shapValue), reverse=True)
        return items

    @staticmethod
    def render_individual_waterfall_ascii(shap_items: List[FeatureSHAPItem], base_val: float, pred_val: float, max_bars: int = 6) -> str:
        lines = [
            f"Individual Prediction Waterfall (Base: {base_val*100:.1f}% -> Output: {pred_val*100:.1f}%)",
            "─" * 60
        ]
        top_items = shap_items[:max_bars]
        max_phi = max((it.absoluteContribution for it in top_items), default=0.1)
        max_phi = max_phi if max_phi > 0 else 0.1

        for it in top_items:
            bar_len = int(round((it.absoluteContribution / max_phi) * 14))
            bar_str = "█" * max(1, bar_len)
            sign = "+" if it.direction == ContributionDirection.POSITIVE else "-"
            lines.append(f"{it.featureName:<26} {bar_str:<14} {sign}{it.absoluteContribution:.4f}")
        return "\n".join(lines)

    def generate_forensic_report(
        self,
        prediction_id: str,
        features: Dict[str, float],
        shap_explanation: SHAPExplanation,
        threat_probability: float,
        predicted_category: str,
        category_confidence: float = 0.91,
        risk_level: str = "HIGH",
        model_name: str = "random_forest",
        model_version: str = "rf-v1.0",
        dataset_version: str = "dataset-v1.0",
        feature_version: str = "feature-v1.0"
    ) -> ComprehensiveXAIForensicReport:
        # 1. Audit Trail
        input_hash = self.calculate_input_hash(features, model_version, feature_version)
        audit = XAIAuditTrail(
            explanationId=shap_explanation.explanationId,
            predictionId=prediction_id,
            modelVersion=model_version,
            datasetVersion=dataset_version,
            featureVersion=feature_version,
            timestamp=shap_explanation.generatedAt,
            inputHash=input_hash,
            shapVersion=str(shap.__version__)
        )

        # 2. Prediction Explanation Card Data
        top_badges = [it.featureName.replace("_", " ").capitalize() for it in shap_explanation.topPositiveFeatures[:4]]
        card = PredictionExplanationCardData(
            predictionId=prediction_id,
            threatProbability=threat_probability,
            threatProbabilityFormatted=f"{round(threat_probability * 100, 1)}%",
            predictedCategory=predicted_category,
            categoryConfidence=category_confidence,
            categoryConfidenceFormatted=f"{round(category_confidence * 100, 1)}%",
            riskLevel=risk_level,
            topFactorBadges=top_badges
        )

        # 3. Evidence Panel & Why Panel
        evidence_panel = self.build_evidence_panel(features)
        why_panel = self.build_why_panel(shap_explanation.features)

        # 4. Visualizations
        waterfall_ascii = self.render_individual_waterfall_ascii(
            shap_explanation.features,
            shap_explanation.baseValue,
            shap_explanation.predictionValue
        )

        # Fetch global summary chart from global engine
        global_report = global_feature_importance_engine.last_report
        global_ascii = global_report.shapAsciiBarChart if global_report else "Global chart not initialized."

        # 5. Natural Language Reasoning
        reasons = [f"{w.directionIndicator} {w.featureLabel}: {w.impactDescription}" for w in why_panel[:4]]
        nl_reasoning = (
            f"The model predicted {predicted_category} with {round(threat_probability*100, 1)}% probability "
            f"because " + ", ".join(reasons) + "."
        )

        report = ComprehensiveXAIForensicReport(
            auditTrail=audit,
            cardData=card,
            evidencePanel=evidence_panel,
            whyThisPredictionPanel=why_panel,
            localWaterfallAscii=waterfall_ascii,
            globalSummaryAscii=global_ascii,
            naturalLanguageReasoning=nl_reasoning
        )

        # Persist report to file
        report_file = REPORTS_DIR / f"report_{prediction_id}.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=2)

        return report

xai_dashboard_engine = XAIDashboardEngine()