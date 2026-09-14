import math
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import uuid

from services.digital_twin.risk.factors.factor_types import AssetCriticalityLevel

class PredictionProvenance(BaseModel):
    predictionId: str
    modelName: str = "RandomForest"
    modelVersion: str = "1.0"
    featureVersion: str = "feature-v1.0"
    datasetVersion: str = "dataset-v1.0"
    predictionTimestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AssetCriticalityConfigItem(BaseModel):
    level: AssetCriticalityLevel
    score: float
    description: str
    version: str = "1.0"

class ThreatAssetContextRecord(BaseModel):
    contextId: str = Field(default_factory=lambda: f"CTX-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    deviceId: str
    deviceType: str
    hostname: str
    ipAddress: str
    macAddress: str
    assetCriticality: AssetCriticalityLevel
    criticalityWeight: float

    # Verified Threat Probability
    threatProbability: float
    threatProbabilityFormatted: str

    # Interim Base Risk Interaction: P_threat * C_asset
    baseContextScore: float
    baseContextScoreFormatted: str

    # Lineage & Provenance
    provenance: PredictionProvenance
    status: str = "VALIDATED"

    @field_validator("threatProbability")
    @classmethod
    def validate_probability(cls, v: float) -> float:
        if v is None:
            raise ValueError("Threat probability cannot be null.")
        if not isinstance(v, (int, float)):
            raise ValueError(f"Threat probability must be numeric, got: {type(v)}")
        if math.isnan(v) or math.isinf(v):
            raise ValueError(f"Threat probability cannot be NaN or Infinity, got: {v}")
        if v < 0.0 or v > 1.0:
            raise ValueError(f"Threat probability must be in range [0.0, 1.0], got: {v}")
        return float(v)

    def to_formatted_card(self) -> str:
        return (
            f"╔════════════════════════════════════════════════════════════════════╗\n"
            f"║              THREAT + ASSET CONTEXT BINDING CARD                   ║\n"
            f"╠════════════════════════════════════════════════════════════════════╣\n"
            f"║ Context ID  : {self.contextId:<26} Status: {self.status:<20} ║\n"
            f"║ Device ID   : {self.deviceId:<26} Host  : {self.hostname:<20} ║\n"
            f"║ Device Type : {self.deviceType:<26} IP    : {self.ipAddress:<20} ║\n"
            f"║ Criticality : {self.assetCriticality.value:<26} Weight: {self.criticalityWeight:<20.2f} ║\n"
            f"╠════════════════════════════════════════════════════════════════════╣\n"
            f"║ Threat Probability : {self.threatProbabilityFormatted:<16} Provenance: {self.provenance.predictionId:<18} ║\n"
            f"║ Model Provenance   : {self.provenance.modelName} (v: {self.provenance.modelVersion}, feat: {self.provenance.featureVersion})       ║\n"
            f"║ Base Context Risk  : {self.baseContextScoreFormatted:<16} (P_threat × C_asset = {self.baseContextScore:.4f})  ║\n"
            f"╚════════════════════════════════════════════════════════════════════╝"
        )