from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ImportanceMethodEnum(str, Enum):
    TREE_IMPORTANCE = "TREE_IMPORTANCE"
    COEFFICIENT_IMPORTANCE = "COEFFICIENT_IMPORTANCE"
    SHAP_GLOBAL_IMPORTANCE = "SHAP_GLOBAL_IMPORTANCE"
    SURROGATE_IMPORTANCE = "SURROGATE_IMPORTANCE"

class FeatureImportanceItem(BaseModel):
    featureName: str
    importance: float
    importanceFormatted: str
    importanceMethod: ImportanceMethodEnum
    rank: int
    modelName: str
    modelVersion: str = "1.0.0"
    datasetVersion: str = "dataset-v1.0"
    featureVersion: str = "feature-v1.0"

class FeatureComparisonItem(BaseModel):
    featureName: str
    nativeImportance: float
    nativeRank: int
    shapImportance: float
    shapRank: int
    rankDelta: int  # nativeRank - shapRank
    interpretation: str

class GlobalImportanceReport(BaseModel):
    reportId: str = Field(default_factory=lambda: f"GIMP-{uuid.uuid4().hex[:8].upper()}")
    modelName: str
    modelVersion: str
    datasetVersion: str = "dataset-v1.0"
    featureVersion: str = "feature-v1.0"
    generatedAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    nativeMethod: ImportanceMethodEnum
    nativeImportances: List[FeatureImportanceItem]
    shapImportances: List[FeatureImportanceItem]
    comparisonTable: List[FeatureComparisonItem]

    nativeAsciiBarChart: str
    shapAsciiBarChart: str

    def to_summary_string(self) -> str:
        return (
            f"Global Importance Report: {self.reportId}\n"
            f"Model: {self.modelName} ({self.modelVersion}) | Method: {self.nativeMethod.value}\n"
            f"\n--- Native Model Importance ---\n{self.nativeAsciiBarChart}\n"
            f"\n--- Global SHAP Importance ---\n{self.shapAsciiBarChart}\n"
        )