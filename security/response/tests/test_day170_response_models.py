import asyncio
import sys
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum, ResponseStatusEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.models.response import (
    CanonicalResponseContract, generate_canonical_response_id
)
from security.response.simulation.response_simulator import response_simulator
from security.response.validation.response_validator import ResponseSafetyValidator

class MockSocket:
    def __init__(self):
        self.messages = []
    async def accept(self):
        pass
    async def send_json(self, data):
        self.messages.append(data)
    async def close(self):
        pass

def run_day170_suite():
    print("=" * 80)
    print("       WEEK 25 - DAY 170: RESPONSE DATA MODELS & CANONICAL CONTRACT AUDIT")
    print("=" * 80 + "\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def test_body():
        mock_ws = MockSocket()
        await websocket_connection_manager.connect(mock_ws)

        try:
            twin_graph_synchronizer._seed_default_twin_state()
            twin_graph_synchronizer.full_synchronization()
            snap = realtime_event_manager.generate_full_twin_snapshot()
            realtime_store_engine.apply_snapshot(snap)

            # 1. Canonical Response ID Format & Monotonic Generation
            print("[1/9] Auditing Canonical Response ID Generation (RESP-YYYYMMDD-XXXXXX)...")
            id1 = generate_canonical_response_id()
            id2 = generate_canonical_response_id()
            pattern = r"^RESP-\d{8}-\d{6}$"

            print(f"    Sample ID 1 : {id1}")
            print(f"    Sample ID 2 : {id2}")

            assert re.match(pattern, id1) is not None
            assert re.match(pattern, id2) is not None
            assert id1 != id2
            print("    [PASS] Canonical response ID format verified.")

            # 2. Rigid Action Enumeration Verification (All 6 Actions)
            print("\n[2/9] Auditing Response Action Enumeration Coverage...")
            expected_actions = [
                ResponseActionType.ISOLATE_DEVICE,
                ResponseActionType.BLOCK_CONNECTION,
                ResponseActionType.DISABLE_SERVICE,
                ResponseActionType.QUARANTINE_ENDPOINT,
                ResponseActionType.INCREASE_SECURITY_LEVEL,
                ResponseActionType.MARK_DEVICE_AT_RISK
            ]
            for act in expected_actions:
                assert act.value in ResponseActionType
                print(f"    Action Verified: {act.value}")
            print("    [PASS] All 6 defensive action types validated.")

            # 3. Canonical Contract Assembly & Triggering Alert Reference
            print("\n[3/9] Auditing Triggering Alert Reference Linkage...")
            rec = response_simulator.generate_recommendation_from_intelligence(
                device_id="WEB-01",
                risk_score=85.0,
                alert_id="ALT-20260916-001",
                prediction_id="PRD-20260916-002",
                category="LATERAL_MOVEMENT"
            )
            contract = response_simulator.create_canonical_response_contract(rec)

            print(f"    Linked Alert ID    : {contract.triggeringAlert.alertId}")
            print(f"    Linked Event Type  : {contract.triggeringAlert.eventType}")
            print(f"    Alert Severity     : {contract.triggeringAlert.severity.value}")

            assert contract.triggeringAlert.alertId == "ALT-20260916-001"
            assert contract.triggeringAlert.severity.value in ("HIGH", "CRITICAL")
            print("    [PASS] Triggering alert schema verified.")

            # 4. Triggering Prediction Reference Linkage
            print("\n[4/9] Auditing Triggering ML Prediction Linkage...")
            print(f"    Linked Prediction ID : {contract.triggeringPrediction.predictionId}")
            print(f"    ML Model Name        : {contract.triggeringPrediction.modelName}")
            print(f"    Predicted Threat Prob: {contract.triggeringPrediction.threatProbability}")

            assert contract.triggeringPrediction.predictionId == "PRD-20260916-002"
            assert contract.triggeringPrediction.threatProbability > 0.0
            print("    [PASS] Triggering ML prediction reference verified.")

            # 5. Canonical Risk Information & Formula Invariance
            print("\n[5/9] Auditing Canonical P*C*V*I Risk Calculation Verification...")
            ra = contract.riskAssessment
            expected_score = round(ra.threatProbability * ra.assetCriticality * ra.vulnerabilityFactor * ra.attackImpact * 100.0, 1)

            print(f"    Threat Prob   : {ra.threatProbability}")
            print(f"    Asset Crit    : {ra.assetCriticality}")
            print(f"    Vuln Factor   : {ra.vulnerabilityFactor}")
            print(f"    Attack Impact : {ra.attackImpact}")
            print(f"    Calculated    : {ra.riskScore} (Expected: {expected_score})")

            assert ra.riskScore == expected_score
            print("    [PASS] Canonical risk formula verified.")

            # 6. Previous / New State Transition Tracking
            print("\n[6/9] Auditing Previous State -> New State Transition...")
            print(f"    Previous State: {contract.previousState}")
            print(f"    Action        : {contract.action.value}")
            print(f"    New State     : {contract.newState}")

            assert contract.previousState in ("NORMAL", "AT_RISK")
            assert contract.newState == "ISOLATED"
            print("    [PASS] State transition correctly tracked.")

            # 7. Operator & Mode Enforcements
            print("\n[7/9] Auditing Operator Attribution & Simulation Mode Guardrail...")
            print(f"    Operator : {contract.operator}")
            print(f"    Mode     : {contract.mode.value}")

            assert contract.operator == "AUTOMATED_SIMULATION"
            assert contract.mode == ExecutionModeEnum.SIMULATION
            print("    [PASS] Operator and simulation mode invariants confirmed.")

            # 8. Execution Result Record & Digital Twin Mutation
            print("\n[8/9] Auditing Simulated Response Execution & Result Record...")
            executed = await response_simulator.execute_simulated_response(rec, operator="SOC_ANALYST")

            print(f"    Execution Status     : {executed.executionStatus.value}")
            print(f"    Result Status        : {executed.result.status}")
            print(f"    Twin Updated         : {executed.result.twinUpdated}")
            print(f"    Affected Connections : {executed.result.affectedConnections}")

            assert executed.executionStatus == ResponseStatusEnum.COMPLETED
            assert executed.result.twinUpdated is True
            assert attack_path_graph.nodes["WEB-01"].securityState == "ISOLATED"
            print("    [PASS] Execution result record populated and Twin mutated.")

            # 9. Clean Baseline Restoration
            print("\n[9/9] Restoring Clean Baseline State...")
            twin_graph_synchronizer._seed_default_twin_state()
            twin_graph_synchronizer.full_synchronization()
            assert attack_path_graph.nodes["WEB-01"].securityState in ("NORMAL", "AT_RISK")
            print("    [PASS] Clean baseline restored.")

        finally:
            await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 170 RESPONSE MODEL & CONTRACT TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day170_suite()