from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class EvidenceSeverityLevel(str, Enum):
    NORMAL = "NORMAL"
    MODERATELY_ELEVATED = "MODERATELY_ELEVATED"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ObservedEvidenceItem(BaseModel):
    featureName: str
    featureLabel: str
    observedValue: float
    unit: str
    severity: EvidenceSeverityLevel
    contextNote: str

class WhyContributionItem(BaseModel):
    featureName: str
    featureLabel: str
    directionIndicator: str  # "↑" or "↓"
    direction: str           # "POSITIVE" or "NEGATIVE"
    shapValue: float
    shapFormatted: str
    impactDescription: str   # "Strong positive contribution", "Slight negative contribution"

class PredictionExplanationCardData(BaseModel):
    cardId: str = Field(default_factory=lambda: f"CARD-{uuid.uuid4().hex[:8].upper()}")
    predictionId: str
    threatProbability: float
    threatProbabilityFormatted: str
    predictedCategory: str
    categoryConfidence: float
    categoryConfidenceFormatted: str
    riskLevel: str
    topFactorBadges: List[str]

class XAIAuditTrail(BaseModel):
    auditId: str = Field(default_factory=lambda: f"AUDIT-{uuid.uuid4().hex[:8].upper()}")
    explanationId: str
    predictionId: str
    modelVersion: str
    datasetVersion: str
    featureVersion: str
    timestamp: str
    inputHash: str
    explanationMethod: str = "SHAP_TreeExplainer"
    shapVersion: str
    featureImportanceMethod: str = "TREE_IMPORTANCE"

class ComprehensiveXAIForensicReport(BaseModel):
    reportId: str = Field(default_factory=lambda: f"REP-XAI-{uuid.uuid4().hex[:8].upper()}")
    auditTrail: XAIAuditTrail
    cardData: PredictionExplanationCardData
    evidencePanel: List[ObservedEvidenceItem]
    whyThisPredictionPanel: List[WhyContributionItem]
    localWaterfallAscii: str
    globalSummaryAscii: str
    naturalLanguageReasoning: str
    limitations: str = "This explanation describes model behaviour and does not prove that an attack occurred."