from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class EnrichedSecurityAlert(BaseModel):
    alertId: str = Field(default_factory=lambda: f"ALT-XAI-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str
    destination: str
    eventType: str = "ML_ATTACK_PREDICTION"
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL

    # Core Threat Quantities
    threatProbability: float
    threatProbabilityFormatted: str
    predictedCategory: str
    categoryConfidence: float
    categoryConfidenceFormatted: str
    riskScore: float
    riskLevel: str

    # Temporal Early-Warning Additions
    futureThreatProbability: Optional[float] = None
    futureThreatProbabilityFormatted: Optional[str] = None
    earlyWarningStatus: Optional[str] = None
    leadTimeFormatted: Optional[str] = None

    # XAI Attributions & Natural Language Evidence
    explanationId: str
    topContributingFeatures: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: str
    evidence: List[str] = Field(default_factory=list)

    # Lineage & Audit
    modelName: str
    modelVersion: str
    status: str = "ACTIVE"

    def to_soc_display(self) -> str:
        factors = "\n".join(f"  * {f['featureName']}: {f['contributionFormatted']} (Val: {f['featureValue']})" for f in self.topContributingFeatures[:4])
        return (
            f"╔══════════════════════════════════════════════════════════════════════════════╗\n"
            f"║                       ENRICHED SECURITY ALERT                                ║\n"
            f"╠══════════════════════════════════════════════════════════════════════════════╣\n"
            f"║ Alert ID: {self.alertId:<30} Severity: {self.severity:<25} ║\n"
            f"║ Target  : {self.destination:<30} Source  : {self.source:<25} ║\n"
            f"║ Threat  : {self.threatProbabilityFormatted:<10} ({self.predictedCategory:<15}) Risk: {self.riskLevel:<8} (Score: {self.riskScore:.1f})   ║\n"
            f"║ Early Warning Status: {str(self.earlyWarningStatus):<18} Lead Time: {str(self.leadTimeFormatted):<20} ║\n"
            f"║ Model   : {self.modelName:<18} (v: {self.modelVersion:<12}) Explanation: {self.explanationId:<10} ║\n"
            f"╠══════════════════════════════════════════════════════════════════════════════╣\n"
            f"║ PRIMARY CONTRIBUTING FACTORS:                                                ║\n"
            f"{factors}\n"
            f"║                                                                              ║\n"
            f"║ EXPLANATION NARRATIVE:                                                       ║\n"
            f"║ {self.explanation[:76]} ║\n"
            f"║ {self.explanation[76:152] if len(self.explanation) > 76 else ''} ║\n"
            f"╚══════════════════════════════════════════════════════════════════════════════╝"
        )