from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class MalformedEveRecord(BaseModel):
    rawInput: str
    lineNumber: int = 0
    errorReason: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)

class EvePipelineIngestResult(BaseModel):
    totalProcessed: int = 0
    validCount: int = 0
    malformedCount: int = 0
    normalizedEventIds: List[str] = Field(default_factory=list)
    malformedRecords: List[MalformedEveRecord] = Field(default_factory=list)