from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class TwinDeviceSecurityState(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    AT_RISK = "AT_RISK"
    COMPROMISED = "COMPROMISED"

class MLSecurityAlert(BaseModel):
    alertId: str = Field(default_factory=lambda: f"ALT-ML-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    alertType: str = "ML_ATTACK_PREDICTION"
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    deviceId: str
    source: str
    destination: str
    threatProbability: float
    threatProbabilityFormatted: str
    predictedCategory: str
    categoryConfidence: float
    categoryConfidenceFormatted: str
    riskScore: float
    riskLevel: str
    rationale: str
    predictionId: str

class DeviceTwinNode(BaseModel):
    deviceId: str
    ipAddress: str
    securityState: TwinDeviceSecurityState = TwinDeviceSecurityState.NORMAL
    threatProbability: float = 0.0
    predictedCategory: str = "NORMAL"
    predictionConfidence: float = 0.0
    riskScore: float = 0.0
    riskLevel: str = "LOW"
    lastPredictionId: Optional[str] = None
    lastPredictionTimestamp: Optional[str] = None
    predictionHistory: List[Dict[str, Any]] = Field(default_factory=list)
    activeAlerts: List[MLSecurityAlert] = Field(default_factory=list)

    def update_security_state(
        self,
        prediction_id: str,
        threat_prob: float,
        category: str,
        confidence: float,
        risk_score: float,
        risk_level: str,
        confirmed_compromise_evidence: bool = False
    ) -> TwinDeviceSecurityState:
        self.threatProbability = threat_prob
        self.predictedCategory = category
        self.predictionConfidence = confidence
        self.riskScore = risk_score
        self.riskLevel = risk_level
        self.lastPredictionId = prediction_id
        self.lastPredictionTimestamp = datetime.now(timezone.utc).isoformat()

        # Append to historical ledger without overwriting
        self.predictionHistory.append({
            "predictionId": prediction_id,
            "timestamp": self.lastPredictionTimestamp,
            "threatProbability": threat_prob,
            "category": category,
            "confidence": confidence,
            "riskScore": risk_score,
            "riskLevel": risk_level
        })

        # Keep history to last 50 entries
        self.predictionHistory = self.predictionHistory[-50:]

        # Guardrail: Compromised requires explicit, verified compromise evidence
        if confirmed_compromise_evidence:
            self.securityState = TwinDeviceSecurityState.COMPROMISED
        elif risk_level in ("HIGH", "CRITICAL") or risk_score >= 60.0:
            self.securityState = TwinDeviceSecurityState.AT_RISK
        elif risk_level == "MEDIUM" or risk_score >= 30.0 or threat_prob >= 0.50:
            self.securityState = TwinDeviceSecurityState.SUSPICIOUS
        else:
            self.securityState = TwinDeviceSecurityState.NORMAL

        return self.securityState