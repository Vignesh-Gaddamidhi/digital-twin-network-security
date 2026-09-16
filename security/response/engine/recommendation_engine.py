from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from security.response.models.action import ResponseActionType
from security.response.models.recommendation import (
    ResponseRecommendation, RecommendationStatusEnum, RecommendationPriorityEnum,
    generate_canonical_recommendation_id
)

class ResponseRecommendationEngine:
    """Evaluates security intelligence, ML predictions, and XAI drivers to recommend safe defensive playbooks."""

    def __init__(self):
        self.recommendation_store: Dict[str, ResponseRecommendation] = {}

    def formulate_recommendation(
        self,
        alert_id: str,
        prediction_id: str,
        device_id: str,
        risk_score: float,
        predicted_category: str = "LATERAL_MOVEMENT",
        prediction_confidence: float = 0.94,
        xai_features: Optional[List[str]] = None,
        has_open_vulnerabilities: bool = False,
        is_critical_asset: bool = True,
        target_link_id: Optional[str] = None,
        target_service: Optional[str] = None
    ) -> ResponseRecommendation:
        current_node = attack_path_graph.get_node(device_id)
        current_state = current_node.securityState if current_node else "NORMAL"
        features = xai_features or [
            "Connection frequency increased significantly",
            "Destination diversity abnormal",
            "Unassigned port probe detected"
        ]

        # 1. Synthesize Explainable Evidence
        evidence = [
            f"Risk Score: {risk_score:.1f} ({'CRITICAL' if risk_score >= 80 else 'HIGH' if risk_score >= 60 else 'MEDIUM'})",
            f"Threat Category: {predicted_category} (Confidence: {prediction_confidence:.1%})",
            f"Asset Posture: State={current_state}, CriticalAsset={is_critical_asset}",
        ]
        evidence.extend([f"XAI Driver: {f}" for f in features])

        # 2. Heuristic Playbook Mapping (Ordered by Specificity)
        if risk_score >= 80.0 or current_state == "COMPROMISED" or predicted_category in ("DATA_EXFILTRATION", "RANSOMWARE"):
            action = ResponseActionType.ISOLATE_DEVICE
            priority = RecommendationPriorityEnum.CRITICAL
            reason = f"Critical threat {predicted_category} and elevated risk ({risk_score:.1f}) require full device containment."

        elif has_open_vulnerabilities and target_service:
            action = ResponseActionType.DISABLE_SERVICE
            priority = RecommendationPriorityEnum.HIGH
            reason = f"Exploitable service '{target_service}' active under threat scenario; disabling service listener."

        elif predicted_category == "PORT_SCAN" or (xai_features and any("port probe" in f.lower() for f in xai_features)):
            action = ResponseActionType.BLOCK_CONNECTION
            priority = RecommendationPriorityEnum.HIGH
            reason = f"Reconnaissance behavior detected; blocking active ingress link to prevent lateral scanning."

        elif (
            predicted_category == "ENDPOINT_ANOMALY"
            or (current_node and getattr(current_node, "deviceType", getattr(current_node, "type", "")).lower() in ("client", "workstation"))
            or device_id.upper().startswith("CLIENT")
        ):
            action = ResponseActionType.QUARANTINE_ENDPOINT
            priority = RecommendationPriorityEnum.HIGH
            reason = f"Host endpoint exhibiting anomalous command execution; enforcing VLAN endpoint quarantine."

        elif risk_score >= 50.0:
            action = ResponseActionType.INCREASE_SECURITY_LEVEL
            priority = RecommendationPriorityEnum.MEDIUM
            reason = f"Moderate security divergence ({risk_score:.1f}); elevating telemetry sampling and IDS inspection."

        else:
            action = ResponseActionType.MARK_DEVICE_AT_RISK
            priority = RecommendationPriorityEnum.LOW
            reason = f"Baseline behavioral anomaly detected; tagging asset as at-risk for proactive tracking."

        level = RiskLevelTier.CRITICAL if risk_score >= 80 else RiskLevelTier.HIGH if risk_score >= 60 else RiskLevelTier.MEDIUM

        rec = ResponseRecommendation(
            recommendationId=generate_canonical_recommendation_id(),
            alertId=alert_id,
            predictionId=prediction_id,
            deviceId=device_id,
            riskScore=risk_score,
            riskLevel=level,
            recommendedAction=action,
            reason=reason,
            evidence=evidence,
            confidence=prediction_confidence,
            priority=priority,
            simulationRequired=True,
            status=RecommendationStatusEnum.PENDING,
            targetLinkId=target_link_id,
            targetService=target_service
        )

        self.recommendation_store[rec.recommendationId] = rec
        return rec

    def transition_status(self, recommendation_id: str, new_status: RecommendationStatusEnum) -> Optional[ResponseRecommendation]:
        if recommendation_id in self.recommendation_store:
            self.recommendation_store[recommendation_id].status = new_status
            return self.recommendation_store[recommendation_id]
        return None

    def get_pending_recommendations(self) -> List[ResponseRecommendation]:
        return [r for r in self.recommendation_store.values() if r.status == RecommendationStatusEnum.PENDING]

response_recommendation_engine = ResponseRecommendationEngine()