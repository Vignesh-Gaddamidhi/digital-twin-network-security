from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class RawSourceEnum(str, Enum):
    SIMULATION = "SIMULATION"
    SURICATA = "SURICATA"
    ZEEK = "ZEEK"
    SECURITY_PIPELINE = "SECURITY_PIPELINE"

class DeduplicationStatusEnum(str, Enum):
    ORIGINAL = "ORIGINAL"
    DUPLICATE = "DUPLICATE"

class RawRecord(BaseModel):
    rawRecordId: str = Field(default_factory=lambda: f"RAW-{uuid.uuid4().hex[:8].upper()}")
    source: RawSourceEnum
    sourceFile: Optional[str] = None
    ingestionTimestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    originalTimestamp: Optional[str] = None
    fingerprint: str
    deduplicationStatus: DeduplicationStatusEnum = DeduplicationStatusEnum.ORIGINAL
    duplicateOf: Optional[str] = None
    rawPayload: Dict[str, Any]
    validationStatus: str = "VALID"
    validationErrors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class RawIngestionSummary(BaseModel):
    batchId: str = Field(default_factory=lambda: f"BATCH-{uuid.uuid4().hex[:8].upper()}")
    source: RawSourceEnum
    sourceFile: Optional[str] = None
    totalRead: int = 0
    validRecords: int = 0
    invalidRecords: int = 0
    duplicatesDetected: int = 0
    persistedCount: int = 0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())