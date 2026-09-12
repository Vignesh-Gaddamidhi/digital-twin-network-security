from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class ModelBinaryLabel(str, Enum):
    NORMAL = "NORMAL"
    ANOMALOUS = "ANOMALOUS"

class ModelMulticlassLabel(str, Enum):
    NORMAL = "NORMAL"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE_LIKE = "BRUTE_FORCE_LIKE"
    DOS_LIKE = "DOS_LIKE"
    DNS_ANOMALY = "DNS_ANOMALY"
    BEACONING = "BEACONING"
    LATERAL_MOVEMENT_LIKE = "LATERAL_MOVEMENT_LIKE"
    EXFILTRATION_LIKE = "EXFILTRATION_LIKE"
    UNKNOWN = "UNKNOWN"

class LabelMethodEnum(str, Enum):
    DETERMINISTIC_SCENARIO = "DETERMINISTIC_SCENARIO"
    RULE_BASED_DETECTION = "RULE_BASED_DETECTION"
    IDS_UNVERIFIED = "IDS_UNVERIFIED"
    BENIGN_BASELINE = "BENIGN_BASELINE"
    MANUAL_INSPECTION = "MANUAL_INSPECTION"

class LabeledDatasetSample(BaseModel):
    sampleId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # --- Predictors X (Strictly sanitized against label leakage) ---
    features: Dict[str, float]
    numericalVector: List[float]

    # --- Ground Truth Targets Y ---
    scenario_label: str = "NORMAL"
    binary_label: ModelBinaryLabel = ModelBinaryLabel.NORMAL
    multiclass_label: ModelMulticlassLabel = ModelMulticlassLabel.NORMAL

    # --- Provenance & Confidence ---
    label_source: str = "SIMULATION"
    label_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    label_method: LabelMethodEnum = LabelMethodEnum.DETERMINISTIC_SCENARIO

    # --- Metadata & Lineage ---
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def get_clean_feature_names(self) -> List[str]:
        return list(self.features.keys())

class LabelReport(BaseModel):
    reportId: str = Field(default_factory=lambda: f"LBL-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    totalSamples: int = 0
    normalSamples: int = 0
    anomalousSamples: int = 0
    unknownLabels: int = 0
    multiclassCounts: Dict[str, int] = Field(default_factory=dict)
    labelSources: Dict[str, int] = Field(default_factory=dict)
    averageConfidence: float = 0.0
    leakageCheckPassed: bool = True