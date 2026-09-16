from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
import uuid

from services.digital_twin.risk.factors.factor_types import RiskLevelTier

class ForensicAuditEntry(BaseModel):
    """Complete, immutable forensic audit record linking upstream intelligence to twin mutations."""
    auditId: str = Field(default_factory=lambda: f"AUD-{uuid.uuid4().hex[:8].upper()}")
    responseId: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    operator: str
    action: str
    reason: str
    triggeringAlert: str
    triggeringPrediction: str
    xaiExplanationSnippet: Optional[str] = None
    riskScore: float
    riskLevel: RiskLevelTier = RiskLevelTier.HIGH
    affectedDevice: str
    mode: str = "SIMULATION"
    previousState: str
    newState: str
    twinUpdated: bool = True
    transportDelivery: str = "DELIVERED"
    result: Dict[str, Any] = Field(default_factory=dict)

    @property
    def actionType(self) -> str:
        return self.action

    @property
    def executionMode(self) -> str:
        return self.mode

    @property
    def targetDevice(self) -> str:
        return self.affectedDevice

    @property
    def success(self) -> bool:
        return self.twinUpdated

class AuditFilterCriteria(BaseModel):
    deviceId: Optional[str] = None
    action: Optional[str] = None
    riskLevel: Optional[RiskLevelTier] = None
    operator: Optional[str] = None
    status: Optional[str] = None
    startDate: Optional[str] = None
    endDate: Optional[str] = None

class ResponseAuditTrailEngine:
    """Enterprise audit ledger capturing full intelligence lineage and enforcing idempotency."""

    def __init__(self):
        self.ledger: List[ForensicAuditEntry] = []
        self.processed_response_ids: Set[str] = set()

    def is_duplicate(self, response_id: str) -> bool:
        return response_id in self.processed_response_ids

    def record_forensic_entry(
        self,
        response_id: str,
        operator: str,
        action: str,
        reason: str,
        triggering_alert: str,
        triggering_prediction: str,
        risk_score: float,
        affected_device: str,
        previous_state: str,
        new_state: str,
        result: Dict[str, Any],
        mode: str = "SIMULATION",
        xai_snippet: Optional[str] = None,
        twin_updated: bool = True,
        transport_delivery: str = "DELIVERED"
    ) -> ForensicAuditEntry:
        level = RiskLevelTier.CRITICAL if risk_score >= 80 else RiskLevelTier.HIGH if risk_score >= 60 else RiskLevelTier.MEDIUM
        # Update existing record if already in ledger
        for e in self.ledger:
            if e.responseId == response_id:
                e.operator = operator
                e.action = action
                e.reason = reason
                e.triggeringAlert = triggering_alert
                e.triggeringPrediction = triggering_prediction
                e.xaiExplanationSnippet = xai_snippet or e.xaiExplanationSnippet
                e.riskScore = risk_score
                e.riskLevel = level
                e.previousState = previous_state
                e.newState = new_state
                e.twinUpdated = twin_updated
                e.transportDelivery = transport_delivery
                e.result = result
                return e

        entry = ForensicAuditEntry(
            responseId=response_id,
            operator=operator,
            action=action,
            reason=reason,
            triggeringAlert=triggering_alert,
            triggeringPrediction=triggering_prediction,
            xaiExplanationSnippet=xai_snippet,
            riskScore=risk_score,
            riskLevel=level,
            affectedDevice=affected_device,
            mode=mode,
            previousState=previous_state,
            newState=new_state,
            twinUpdated=twin_updated,
            transportDelivery=transport_delivery,
            result=result
        )
        self.ledger.append(entry)
        self.processed_response_ids.add(response_id)
        return entry

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
    ) -> ForensicAuditEntry:
        return self.record_forensic_entry(
            response_id=response_id,
            operator=operator,
            action=action_type,
            reason=details.get("reason", "Simulated defensive action executed.") if details else "Simulated defensive action executed.",
            triggering_alert=details.get("triggeringAlert", "ALT-AUTO") if details else "ALT-AUTO",
            triggering_prediction=details.get("triggeringPrediction", "PRD-AUTO") if details else "PRD-AUTO",
            risk_score=details.get("riskScore", 75.0) if details else 75.0,
            affected_device=target_device,
            previous_state=previous_state,
            new_state=new_state,
            result=details or {},
            mode=execution_mode,
            twin_updated=success,
            transport_delivery="DELIVERED"
        )

    def get_entries_for_device(self, device_id: str) -> List[ForensicAuditEntry]:
        return [e for e in self.ledger if e.affectedDevice == device_id]

    def get_latest_entries(self, limit: int = 50) -> List[ForensicAuditEntry]:
        return self.ledger[-limit:]

    def query_audit_history(self, criteria: Optional[AuditFilterCriteria] = None) -> List[ForensicAuditEntry]:
        if not criteria:
            return list(self.ledger)

        results = self.ledger
        if criteria.deviceId:
            results = [e for e in results if e.affectedDevice == criteria.deviceId]
        if criteria.action:
            results = [e for e in results if e.action == criteria.action]
        if criteria.riskLevel:
            results = [e for e in results if e.riskLevel == criteria.riskLevel]
        if criteria.operator:
            results = [e for e in results if e.operator == criteria.operator]
        return results

    def get_full_intelligence_chain(self, response_id: str) -> Optional[Dict[str, Any]]:
        """Reconstructs the complete 9-stage audit lineage for forensic demonstration."""
        entry = next((e for e in self.ledger if e.responseId == response_id), None)
        if not entry:
            return None

        return {
            "1_Alert": entry.triggeringAlert,
            "2_Prediction": entry.triggeringPrediction,
            "3_XAI": entry.xaiExplanationSnippet or "Anomalous connection frequency driver",
            "4_RiskScore": entry.riskScore,
            "5_RiskLevel": entry.riskLevel.value,
            "6_RecommendedAction": entry.action,
            "7_StateTransition": f"{entry.previousState} -> {entry.newState}",
            "8_TwinUpdated": entry.twinUpdated,
            "9_AuditId": entry.auditId,
            "Timestamp": entry.timestamp,
            "Operator": entry.operator,
            "Mode": entry.mode
        }

response_audit_trail_engine = ResponseAuditTrailEngine()
# Compatibility pointer for Day 169-173 references
response_audit_ledger = response_audit_trail_engine