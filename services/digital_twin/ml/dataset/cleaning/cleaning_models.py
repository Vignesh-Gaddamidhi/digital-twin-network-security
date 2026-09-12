from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class FieldCorrectionAudit(BaseModel):
    recordId: str
    fieldName: str
    originalValue: Any
    correctedValue: Any
    correctionReason: str

class RecordRejectionAudit(BaseModel):
    recordId: str
    rejectionReason: str
    rawRecord: Dict[str, Any]

class CleaningReport(BaseModel):
    reportId: str = Field(default_factory=lambda: f"CLR-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    totalRecords: int = 0
    validRecords: int = 0
    invalidRecords: int = 0
    duplicatesHandled: int = 0
    missingValuesEncountered: int = 0
    correctedValuesCount: int = 0
    rejectedRecordsCount: int = 0
    corrections: List[FieldCorrectionAudit] = Field(default_factory=list)
    rejections: List[RecordRejectionAudit] = Field(default_factory=list)