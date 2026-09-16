from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid

class AuditEntry(BaseModel):
    auditId: str = Field(default_factory=lambda: f"AUD-{uuid.uuid4().hex[:8].upper()}")
    responseId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    operator: str
    actionType: str
    targetDevice: str
    previousState: str
    newState: str
    executionMode: str
    validationResult: str
    success: bool
    details: Dict[str, Any] = Field(default_factory=dict)

class ResponseAuditLedger:
    """Tamper-evident audit ledger capturing every response recommendation, simulation, and rejection."""

    def __init__(self):
        self.ledger: List[AuditEntry] = []

    def record_entry(
        self,
        response_id: str,
        operator: str,
        action_type: str,
        target_device: str,
        previous_state: str,
        new_state: str,
        execution_mode: str,
        validation_result: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEntry:
        entry = AuditEntry(
            responseId=response_id,
            operator=operator,
            actionType=action_type,
            targetDevice=target_device,
            previousState=previous_state,
            newState=new_state,
            executionMode=execution_mode,
            validationResult=validation_result,
            success=success,
            details=details or {}
        )
        self.ledger.append(entry)
        return entry

    def get_entries_for_device(self, device_id: str) -> List[AuditEntry]:
        return [e for e in self.ledger if e.targetDevice == device_id]

    def get_latest_entries(self, limit: int = 50) -> List[AuditEntry]:
        return self.ledger[-limit:]

response_audit_ledger = ResponseAuditLedger()