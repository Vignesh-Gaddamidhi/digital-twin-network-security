import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[5]
XAI_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "xai"
ENRICHED_EXP_FILE = XAI_ARTIFACTS_DIR / "enriched_explanations.json"

from services.digital_twin.ml.xai.shap.shap_models import FeatureSHAPItem, ContributionDirection
from services.digital_twin.ml.xai.explanations.enriched_explanation_models import EnrichedPredictionExplanation

class PredictionExplanationEngine:
    """Converts mathematical feature attributions and telemetry into human-readable cybersecurity evidence."""

    FEATURE_TEMPLATES_POSITIVE = {
        "connection_frequency": "connection frequency increased significantly relative to the learned baseline",
        "destination_diversity": "destination diversity increased, indicating communication with a broader set of endpoints than expected",
        "unique_destination_ports": "unusual destination-port activity was observed across multiple targets",
        "failed_connections": "the number of failed connection attempts increased",
        "packet_rate": "packet transmission rate surged beyond normal baseline parameters",
        "bytes": "transmitted byte volume showed an unexpected upward surge",
        "bytes_per_second": "bandwidth consumption rate escalated sharply",
        "dns_frequency": "DNS query activity deviated from the expected baseline pattern",
        "port_other_ratio": "traffic shifted toward non-standard service ports",
        "flow_duration": "session duration deviated from typical flow lengths"
    }

    FEATURE_TEMPLATES_NEGATIVE = {
        "flow_duration": "session duration remained within expected baseline limits",
        "dns_frequency": "DNS request frequency showed normal query behaviour",
        "failed_connections": "failed connection count remained low and stable",
        "packet_rate": "packet rate remained within calm baseline bounds",
        "tcp_ratio": "protocol balance conformed to standard TCP distribution",
        "destination_diversity": "destination diversity remained focused on standard gateways"
    }

    def __init__(self, artifacts_dir: Path = XAI_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.history: List[EnrichedPredictionExplanation] = []

    def _interpret_feature(self, item: FeatureSHAPItem) -> str:
        fn = item.featureName.lower()
        if item.direction == ContributionDirection.POSITIVE:
            template = self.FEATURE_TEMPLATES_POSITIVE.get(
                fn, f"{item.featureName.replace('_', ' ')} showed elevated activity"
            )
            return f"{template} (observed: {item.featureValue:.2f}, contribution: {item.shapValueFormatted})"
        else:
            template = self.FEATURE_TEMPLATES_NEGATIVE.get(
                fn, f"{item.featureName.replace('_', ' ')} remained within expected tolerances"
            )
            return f"{template} (observed: {item.featureValue:.2f}, mitigation: {item.shapValueFormatted})"

    def generate_explanation(
        self,
        prediction_id: str,
        threat_probability: float,
        predicted_category: str,
        category_confidence: float,
        risk_level: str,
        shap_items: List[FeatureSHAPItem]
    ) -> EnrichedPredictionExplanation:
        # Separate positive (threat drivers) from negative (mitigators)
        pos_items = [it for it in shap_items if it.direction == ContributionDirection.POSITIVE]
        neg_items = [it for it in shap_items if it.direction == ContributionDirection.NEGATIVE]

        pos_items.sort(key=lambda x: abs(x.shapValue), reverse=True)
        neg_items.sort(key=lambda x: abs(x.shapValue), reverse=True)

        # 1. Generate Short Explanation (Executive Summary)
        # Prioritize category-relevant features in top narrative
        category_relevance = {
            "DNS_ANOMALY": ["dns_frequency", "dns_queries", "port_53_ratio"],
            "PORT_SCAN": ["connection_frequency", "destination_diversity", "unique_destination_ports", "failed_connections"],
            "DOS_LIKE": ["packet_rate", "bytes_per_second", "bytes"],
            "BEACONING": ["connection_frequency", "flow_duration", "tcp_ratio"],
            "LATERAL_MOVEMENT_LIKE": ["destination_diversity", "unique_destination_ratio"],
            "EXFILTRATION_LIKE": ["bytes", "bytes_per_second", "flow_duration"]
        }
        
        target_keys = category_relevance.get(predicted_category, [])
        # Include category items that either have positive SHAP or elevated positive telemetry
        cat_items = [it for it in shap_items if it.featureName in target_keys and (it.direction == ContributionDirection.POSITIVE or it.featureValue >= 1.0)]
        other_pos = [it for it in pos_items if it.featureName not in target_keys]
        ordered_pos = cat_items + other_pos

        top_pos_names = [it.featureName.replace("_", " ") for it in ordered_pos[:3]]
        if threat_probability >= 0.50:
            if top_pos_names:
                summary = f"Threat probability increased mainly due to abnormal {', '.join(top_pos_names[:-1]) + ' and ' + top_pos_names[-1] if len(top_pos_names) > 1 else top_pos_names[0]}."
            else:
                summary = f"Threat probability elevated based on cumulative marginal deviations consistent with {predicted_category}."
        else:
            summary = "Threat probability remains low; network telemetry aligns with normal learned benign baselines."

        # 2. Generate Detailed Explanation (Analyst Narrative)
        supporting_evidence = []
        detailed_paragraphs = []

        if ordered_pos:
            primary_evidence = self.FEATURE_TEMPLATES_POSITIVE.get(ordered_pos[0].featureName, ordered_pos[0].featureName.replace("_", " ") + " was elevated")
            detailed_p1 = f"The model predicted elevated threat probability ({round(threat_probability * 100, 1)}%) primarily because {primary_evidence}."

            secondary_clauses = []
            for it in ordered_pos[1:4]:
                clause = self.FEATURE_TEMPLATES_POSITIVE.get(it.featureName, it.featureName.replace("_", " ") + " also increased")
                secondary_clauses.append(clause)

            if secondary_clauses:
                detailed_p2 = f"Additionally, {', while '.join(secondary_clauses)} provided reinforcing positive evidence."
            else:
                detailed_p2 = ""

            detailed_paragraphs.extend([detailed_p1, detailed_p2])

            for it in pos_items[:5]:
                supporting_evidence.append(self._interpret_feature(it))

        if neg_items:
            neg_clauses = [self.FEATURE_TEMPLATES_NEGATIVE.get(it.featureName, it.featureName.replace("_", " ") + " was normal") for it in neg_items[:2]]
            detailed_p3 = f"Conversely, {' and '.join(neg_clauses)} acted as mitigating baseline evidence."
            detailed_paragraphs.append(detailed_p3)

            for it in neg_items[:3]:
                supporting_evidence.append(self._interpret_feature(it))

        detailed_explanation = " ".join([p for p in detailed_paragraphs if p])

        # 3. Generate Technical Explanation (Attribution Matrix)
        tech_lines = ["Top contributing features:"]
        for it in pos_items[:5]:
            tech_lines.append(f"  - {it.featureName:<26}: {it.shapValueFormatted} (Value: {it.featureValue})")
        if neg_items:
            tech_lines.append("Top mitigating features:")
            for it in neg_items[:3]:
                tech_lines.append(f"  - {it.featureName:<26}: {it.shapValueFormatted} (Value: {it.featureValue})")
        technical_explanation = "\n".join(tech_lines)

        explanation = EnrichedPredictionExplanation(
            predictionId=prediction_id,
            threatProbability=threat_probability,
            threatProbabilityFormatted=f"{round(threat_probability * 100, 1)}%",
            predictedCategory=predicted_category,
            categoryConfidence=category_confidence,
            categoryConfidenceFormatted=f"{round(category_confidence * 100, 1)}%",
            riskLevel=risk_level,
            summary=summary,
            detailedExplanation=detailed_explanation,
            technicalExplanation=technical_explanation,
            topPositiveContributors=pos_items[:5],
            topNegativeContributors=neg_items[:3],
            supportingEvidence=supporting_evidence,
            confidence="HIGH" if category_confidence >= 0.80 else "MEDIUM",
            limitations="This explanation describes model behaviour and does not prove that an attack occurred."
        )

        self.history.append(explanation)
        self._persist_explanation(explanation)
        return explanation

    def _persist_explanation(self, explanation: EnrichedPredictionExplanation):
        existing = []
        if ENRICHED_EXP_FILE.exists():
            try:
                with open(ENRICHED_EXP_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(explanation.model_dump())
        existing = existing[-100:]
        with open(ENRICHED_EXP_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.history.clear()
        if ENRICHED_EXP_FILE.exists():
            try:
                ENRICHED_EXP_FILE.unlink()
            except Exception:
                pass

prediction_explanation_engine = PredictionExplanationEngine()