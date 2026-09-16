from typing import Tuple, Optional
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from security.response.models.action import ExecutionModeEnum, ResponseActionType
from security.response.models.response import ResponseExecutionRecord

class ResponseSafetyValidator:
    """Validates response integrity and blocks real-world execution requests."""

    VALID_STATE_TRANSITIONS = {
        "NORMAL": ["MONITORED", "AT_RISK", "ISOLATED", "QUARANTINED"],
        "MONITORED": ["SUSPICIOUS", "AT_RISK", "ISOLATED", "NORMAL"],
        "SUSPICIOUS": ["AT_RISK", "ISOLATED", "QUARANTINED", "MONITORED"],
        "AT_RISK": ["COMPROMISED", "ISOLATED", "QUARANTINED", "NORMAL"],
        "COMPROMISED": ["ISOLATED", "QUARANTINED", "NORMAL"],
        "ISOLATED": ["NORMAL", "MONITORED"],
        "QUARANTINED": ["NORMAL", "MONITORED"],
    }

    @classmethod
    def validate_execution_request(cls, record: ResponseExecutionRecord) -> Tuple[bool, str]:
        # 1. Hard Safety Boundary: Reject REAL network execution requests
        if record.executionMode != ExecutionModeEnum.SIMULATION:
            return False, "SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED: Only SIMULATION mode is permitted."

        # 2. Device Existence Validation
        if record.affectedDevice not in attack_path_graph.nodes:
            return False, f"DEVICE_NOT_FOUND: Device '{record.affectedDevice}' does not exist in Digital Twin graph."

        # 3. Intelligence Preconditions Validation
        if not record.triggeringAlert or not record.triggeringPrediction:
            return False, "INTELLIGENCE_PRECONDITION_FAILED: Missing triggering alert or prediction ID."

        if record.riskScore < 0.0 or record.riskScore > 100.0:
            return False, "INVALID_RISK_SCORE: Risk score must be between 0.0 and 100.0."

        # 4. State Transition Legality
        prev_st = record.previousState.upper()
        new_st = record.newState.upper()
        if prev_st in cls.VALID_STATE_TRANSITIONS:
            if new_st != prev_st and new_st not in cls.VALID_STATE_TRANSITIONS[prev_st]:
                return False, f"ILLEGAL_STATE_TRANSITION: Cannot transition from {prev_st} to {new_st}."

        # 5. Action Type Match
        if record.actionType not in ResponseActionType:
            return False, f"UNKNOWN_ACTION_TYPE: Action '{record.actionType}' is invalid."

        return True, "VALIDATION_SUCCESSFUL"