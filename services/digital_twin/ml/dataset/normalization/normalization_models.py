from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class NormalizationMethodEnum(str, Enum):
    STANDARD_SCALER = "STANDARD_SCALER"
    MINMAX_SCALER = "MINMAX_SCALER"

class FeatureScaleParam(BaseModel):
    featureName: str
    mean: float
    stdDev: float
    minVal: float
    maxVal: float

class ScalerArtifact(BaseModel):
    scalerId: str = Field(default_factory=lambda: f"SCL-{uuid.uuid4().hex[:8].upper()}")
    version: str = "1.0.0"
    method: NormalizationMethodEnum = NormalizationMethodEnum.STANDARD_SCALER
    fittedOnSamplesCount: int
    fittedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    featureOrder: List[str]
    parameters: Dict[str, FeatureScaleParam]

class NormalizedSampleRecord(BaseModel):
    sampleId: str
    split: str  # TRAIN | TEST
    timestamp: str
    rawFeatures: Dict[str, float]
    normalizedFeatures: Dict[str, float]
    normalizedVector: List[float]
    scenario_label: str
    binary_label: str
    multiclass_label: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class FinalDatasetQualityReport(BaseModel):
    datasetVersion: str = "1.0.0"
    generatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trainSamplesCount: int
    testSamplesCount: int
    featureCount: int
    classDistributionTrain: Dict[str, int]
    classDistributionTest: Dict[str, int]
    zeroLeakageVerified: bool = True
    varianceFlooringAppliedCount: int = 0
    scalerFittedExclusivelyOnTrain: bool = True
    overallQualityStatus: str = "PASSED_PRODUCTION_GRADE"