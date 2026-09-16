from typing import Tuple
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from security.response.models.action import ExecutionModeEnum, ResponseActionType
from security.response.models.response import CanonicalResponseContract
from security.response.engine.state_transition_engine import state_transition_engine

class ResponseSafetyValidator:
    """Validates response integrity against the canonical contract and blocks live network actions."""

    @classmethod
    def validate_canonical_response(cls, resp: CanonicalResponseContract) -> Tuple[bool, str]:
        # 1. Hard Safety Boundary: Reject REAL network execution requests
        if resp.mode != ExecutionModeEnum.SIMULATION:
            return False, "SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED: Only SIMULATION mode is permitted."

        # 2. Canonical Identifier Validation
        if not resp.responseId.startswith("RESP-"):
            return False, f"INVALID_RESPONSE_ID: Identifier '{resp.responseId}' does not conform to canonical format."

        # 3. Target Device Validation
        if resp.affectedDevice not in attack_path_graph.nodes:
            return False, f"DEVICE_NOT_FOUND: Device '{resp.affectedDevice}' does not exist in Digital Twin graph."

        # 4. Intelligence Preconditions Validation
        if not resp.triggeringAlert.alertId or not resp.triggeringPrediction.predictionId:
            return False, "INTELLIGENCE_PRECONDITION_FAILED: Triggering alert and prediction IDs are required."

        # 5. Canonical Risk Formula Check (Risk = P * C * V * I)
        rb = resp.riskAssessment
        expected_score = round(rb.threatProbability * rb.assetCriticality * rb.vulnerabilityFactor * rb.attackImpact * 100.0, 1)
        if abs(rb.riskScore - expected_score) > 0.5:
            return False, f"RISK_FORMULA_MISMATCH: Provided riskScore ({rb.riskScore}) does not match P*C*V*I calculation ({expected_score})."

        # 6. State Transition Legality Check
        is_legal, resolved_st, reason = state_transition_engine.resolve_target_state(resp.action, resp.previousState)
        if not is_legal:
            return False, f"ILLEGAL_STATE_TRANSITION: {reason}"

        return True, "VALIDATION_SUCCESSFUL"