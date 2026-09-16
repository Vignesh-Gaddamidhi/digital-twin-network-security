# Day 170: Response Data Models & Complete Response Contract

## 1. Canonical Response Envelope
Every response executed across the Digital Twin uses a structured schema:

CanonicalResponseContract
├── responseId: RESP-YYYYMMDD-XXXXXX (Monotonically unique)
├── action: ISOLATE_DEVICE | BLOCK_CONNECTION | DISABLE_SERVICE |
│           QUARANTINE_ENDPOINT | INCREASE_SECURITY_LEVEL | MARK_DEVICE_AT_RISK
├── reason: Explicit justification text
├── triggeringAlert: Linked IDS / Security Pipeline Alert Record
├── triggeringPrediction: Linked ML Classifier & Forecaster Record
├── riskAssessment: Composite Risk Score + P * C * V * I factor breakdown
├── affectedDevice: Canonical target hostname / ID
├── timestamp: ISO 8601 UTC timestamp
├── previousState: Canonical node state before mutation
├── newState: Resulting node state applied to Digital Twin
├── operator: "AUTOMATED_SIMULATION" | "SOC_ANALYST" | "ADMIN"
├── mode: ExecutionModeEnum.SIMULATION (Enforced)
├── result: Structured execution outcome (status, twinUpdated, affected edges)
└── auditEntryId: Foreign key reference into ResponseAuditLedger


## 2. Hard Invariants
1. **Zero Unreferenced Actions**: Responses without valid `triggeringAlert`, `triggeringPrediction`, and `riskAssessment` payloads fail validation.
2. **Deterministic Identifier Scheme**: Formatted strictly as `RESP-YYYYMMDD-XXXXXX` using microsecond-precision sequence counters.
3. **Immutability After Execution**: Once marked `COMPLETED` or `REJECTED`, the response record is frozen and referenced in the immutable audit ledger.