from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class SplitStrategyEnum(str, Enum):
    TEMPORAL = "TEMPORAL"
    GROUP = "GROUP"
    STRATIFIED = "STRATIFIED"
    RANDOM = "RANDOM"

class PartitionEnum(str, Enum):
    TRAIN = "TRAIN"
    TEST = "TEST"

class SplitSampleRecord(BaseModel):
    sampleId: str
    split: PartitionEnum
    splitStrategy: SplitStrategyEnum
    timestamp: str
    groupId: str
    scenarioId: Optional[str] = None
    features: Dict[str, float]
    numericalVector: List[float]
    binary_label: str
    multiclass_label: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SplitMetadata(BaseModel):
    splitId: str = Field(default_factory=lambda: f"SPLIT-{uuid.uuid4().hex[:8].upper()}")
    datasetVersion: str = "1.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    strategy: SplitStrategyEnum
    trainRatio: float = 0.80
    testRatio: float = 0.20
    totalSamples: int = 0
    trainSamplesCount: int = 0
    testSamplesCount: int = 0
    trainGroupCount: int = 0
    testGroupCount: int = 0
    trainClassDistribution: Dict[str, int] = Field(default_factory=dict)
    testClassDistribution: Dict[str, int] = Field(default_factory=dict)
    leakageAudited: bool = True
    disjointSamplesPassed: bool = True
    disjointGroupsPassed: bool = True
    temporalIsolationPassed: bool = True
    summary: str = "Train/Test split created cleanly without detected data leakage"