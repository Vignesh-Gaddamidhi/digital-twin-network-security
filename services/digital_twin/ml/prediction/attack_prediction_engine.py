from typing import Dict, Any, Optional, List
import numpy as np

from services.digital_twin.ml.prediction.prediction_models import (
    AttackPrediction, ThreatClassEnum, PredictedAttackCategory,
    RiskLevelEnum, PredictionStatusEnum, PredictionEvidence
)
from services.digital_twin.ml.risk.risk_synthesizer import risk_synthesizer

class AttackPredictionEngine:
    """Core prediction pipeline integrating binary threat probability, multi-class categorizer, and risk synthesizer."""

    def __init__(self):
        self.prediction_history: List[AttackPrediction] = []

    def generate_prediction(
        self,
        features: Dict[str, float],
        source: str,
        destination: str,
        device_id: str = "DEVICE-01",
        device_criticality: float = 0.5,
        network_exposure: float = 0.5,
        binary_threat_prob: Optional[float] = None,
        multiclass_probabilities: Optional[Dict[str, float]] = None
    ) -> AttackPrediction:
        # 1. Evaluate or infer Threat Probability
        pkt_rate = features.get("packet_rate", 0.0)
        byte_rate = features.get("bytes_per_second", 0.0)
        failed_conn = features.get("failed_connections", 0.0)

        if binary_threat_prob is not None:
            threat_p = float(binary_threat_prob)
        else:
            # Baseline deterministic heuristic estimation if model probability tensor not injected
            if pkt_rate > 200.0 or byte_rate > 100000.0 or failed_conn >= 5.0:
                threat_p = 0.92
            elif pkt_rate > 50.0 or byte_rate > 20000.0:
                threat_p = 0.65
            else:
                threat_p = 0.05

        threat_p = round(max(0.0, min(1.0, threat_p)), 4)
        t_class = ThreatClassEnum.THREAT if threat_p >= 0.50 else ThreatClassEnum.NORMAL

        # 2. Evaluate or infer Multi-class Attack Category & Confidence
        if multiclass_probabilities:
            top_cat_key = max(multiclass_probabilities, key=multiclass_probabilities.get)
            cat_conf = multiclass_probabilities[top_cat_key]
            try:
                pred_cat = PredictedAttackCategory(top_cat_key)
            except ValueError:
                pred_cat = PredictedAttackCategory.NETWORK_INTRUSION
        else:
            if t_class == ThreatClassEnum.NORMAL:
                pred_cat = PredictedAttackCategory.NORMAL
                cat_conf = 0.98
            else:
                if features.get("port_other_ratio", 0.0) > 0.4 or features.get("unique_destination_ports", 1) >= 5:
                    pred_cat = PredictedAttackCategory.PORT_SCAN
                    cat_conf = 0.89
                elif failed_conn >= 4:
                    pred_cat = PredictedAttackCategory.BRUTE_FORCE_LIKE
                    cat_conf = 0.85
                elif features.get("dns_frequency", 0.0) > 5.0:
                    pred_cat = PredictedAttackCategory.DNS_ANOMALY
                    cat_conf = 0.90
                elif byte_rate > 200000.0 and features.get("bytes", 0) > 200000:
                    pred_cat = PredictedAttackCategory.EXFILTRATION_LIKE
                    cat_conf = 0.88
                elif pkt_rate > 150.0:
                    pred_cat = PredictedAttackCategory.DOS_LIKE
                    cat_conf = 0.91
                else:
                    pred_cat = PredictedAttackCategory.NETWORK_INTRUSION
                    cat_conf = 0.75

        cat_conf = round(max(0.0, min(1.0, cat_conf)), 4)

        # 3. Contextual Risk Synthesis
        risk_score, risk_lvl, status = risk_synthesizer.calculate_risk(
            threat_prob=threat_p,
            category=pred_cat,
            confidence=cat_conf,
            device_criticality=device_criticality,
            network_exposure=network_exposure
        )

        # 4. Formulate Evidence
        top_feats = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
        evidence = PredictionEvidence(
            topContributingFeatures=[k for k, _ in top_feats],
            featureValues={k: round(v, 2) for k, v in top_feats},
            rationale=f"Observation exhibited elevated {top_feats[0][0]} ({round(top_feats[0][1], 2)}) mapping to {pred_cat.value}."
        )

        prediction = AttackPrediction(
            deviceId=device_id,
            source=source,
            destination=destination,
            threatProbability=threat_p,
            threatClass=t_class,
            predictedCategory=pred_cat,
            categoryConfidence=cat_conf,
            riskScore=risk_score,
            riskLevel=risk_lvl,
            evidence=evidence,
            predictionStatus=status,
            metadata={"deviceCriticality": device_criticality, "networkExposure": network_exposure}
        )

        self.prediction_history.append(prediction)
        return prediction

    def clear(self):
        self.prediction_history.clear()

attack_prediction_engine = AttackPredictionEngine()