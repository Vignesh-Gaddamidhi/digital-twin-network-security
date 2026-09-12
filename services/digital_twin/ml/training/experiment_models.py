from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ModelEvaluationMetrics(BaseModel):
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1Score: float = 0.0
    rocAuc: Optional[float] = None
    confusionMatrix: List[List[int]] = Field(default_factory=list)  # [[TN, FP], [FN, TP]]
    truePositives: int = 0
    falsePositives: int = 0
    trueNegatives: int = 0
    falseNegatives: int = 0

class ExperimentMetadata(BaseModel):
    experimentId: str = Field(default_factory=lambda: f"EXP-{uuid.uuid4().hex[:8].upper()}")
    datasetVersion: str = "dataset-v1.0"
    featureVersion: str = "feat-v1"
    splitVersion: str = "split-v1"
    normalizationVersion: str = "norm-v1"
    modelName: str
    modelVersion: str = "1.0.0"
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)
    trainingTimestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    randomSeed: int = 42
    trainingRecordsCount: int = 0
    testingRecordsCount: int = 0
    featureCount: int = 20
    featureNames: List[str] = Field(default_factory=list)
    metrics: Optional[ModelEvaluationMetrics] = None
    artifactPath: Optional[str] = None