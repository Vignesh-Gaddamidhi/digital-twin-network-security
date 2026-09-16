import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum, ResponseStatusEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.models.response import ResponseExecutionRecord
from security.response.validation.response_validator import ResponseSafetyValidator
from security.response.audit.response_audit import response_audit_ledger
from security.response.simulation.response_simulator import response_simulator

class MockSocket:
    def __init__(self):
        self.messages = []
    async def accept(self):
        pass
    async def send_json(self, data):
        self.messages.append(data)
    async def close(self):
        pass

def run_day169_suite():
    print("=" * 80)
    print("       WEEK 25 - DAY 169: RESPONSE SIMULATION ARCHITECTURE & SAFETY AUDIT")
    print("=" * 80 + "\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def test_body():
        mock_ws = MockSocket()
        await websocket_connection_manager.connect(mock_ws)

        try:
            twin_graph_synchronizer._seed_default_twin_state()
            twin_graph_synchronizer.full_synchronization()
            device_3d_renderer_engine.sync_devices_from_twin()

            from frontend.realtime.realtime_event_manager import realtime_event_manager
            snap = realtime_event_manager.generate_full_twin_snapshot()
            realtime_store_engine.apply_snapshot(snap)

            # 1. Recommendation Generation from Full Intelligence Chain
            print("[1/8] Auditing Recommendation Derivation from Detection & Risk...")
            rec = response_simulator.generate_recommendation_from_intelligence(
                device_id="WEB-01",
                risk_score=84.5,
                alert_id="ALT-101",
                prediction_id="PRD-202",
                category="LATERAL_MOVEMENT",
                explanation="Pivoting behavior observed touching database interfaces."
            )
            print(f"    Recommendation ID: {rec.recommendationId}")
            print(f"    Action Type      : {rec.actionType.value}")
            print(f"    Target Device    : {rec.targetDeviceId}")
            print(f"    Reason           : {rec.reason}")

            assert rec.actionType == ResponseActionType.ISOLATE_DEVICE
            assert rec.triggeringAlertId == "ALT-101"
            assert rec.triggeringPredictionId == "PRD-202"
            print("    [PASS] Recommendation generated strictly preserving intelligence preconditions.")

            # 2. Hard Safety Boundary: Rejection of REAL Mode Execution
            print("\n[2/8] Auditing Hard Safety Boundary (Blocking REAL Mode Execution)...")
            rec_real_attempt = ResponseRecommendation(
                actionType=ResponseActionType.ISOLATE_DEVICE,
                targetDeviceId="WEB-01",
                confidenceScore=0.95,
                riskScore=85.0,
                reason="Attempting unauthorized live physical network modification",
                triggeringAlertId="ALT-101",
                triggeringPredictionId="PRD-202",
                xaiExplanationSnippet="Direct hardware execution probe."
            )
            res_rejected = await response_simulator.execute_simulated_response(
                recommendation=rec_real_attempt,
                execution_mode=ExecutionModeEnum.REAL,
                operator="MALICIOUS_ACTOR_OR_ACCIDENTAL_LIVE_TRIGGER"
            )
            print(f"    Execution Mode Attempted : {res_rejected.executionMode.value}")
            print(f"    Result Status            : {res_rejected.status.value}")
            print(f"    Summary                  : {res_rejected.resultSummary}")

            assert res_rejected.status == ResponseStatusEnum.REJECTED
            assert "SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED" in res_rejected.resultSummary
            print("    [PASS] Non-simulation execution permanently blocked by safety validator.")

            # 3. Safe Simulation Execution Lifecycle
            print("\n[3/8] Auditing Safe Simulated Response Execution Lifecycle...")
            res_sim = await response_simulator.execute_simulated_response(
                recommendation=rec,
                execution_mode=ExecutionModeEnum.SIMULATION,
                operator="SOC_LEAD_ANALYST"
            )
            print(f"    Response ID   : {res_sim.responseId}")
            print(f"    Final Status  : {res_sim.status.value}")
            print(f"    State Change  : {res_sim.previousState} -> {res_sim.newState}")
            print(f"    Audit Entry ID: {res_sim.auditEntryId}")

            assert res_sim.status == ResponseStatusEnum.COMPLETED
            assert res_sim.newState == "ISOLATED"
            assert res_sim.auditEntryId is not None
            print("    [PASS] Full simulated response executed through APPLIED_TO_TWIN to COMPLETED.")

            # 4. Canonical Digital Twin Graph Mutation
            print("\n[4/8] Auditing Canonical Digital Twin State Mutation Invariant...")
            twin_node_state = attack_path_graph.nodes["WEB-01"].securityState
            print(f"    Canonical Twin WEB-01 State: {twin_node_state}")
            assert twin_node_state == "ISOLATED"
            print("    [PASS] Simulated response mutated Canonical Twin without touching physical networks.")

            # 5. Immutable Audit Ledger Verification
            print("\n[5/8] Auditing Tamper-Evident Audit Ledger Record...")
            entries = response_audit_ledger.get_entries_for_device("WEB-01")
            latest_audit = entries[-1]
            print(f"    Audit ID       : {latest_audit.auditId}")
            print(f"    Action         : {latest_audit.actionType}")
            print(f"    Operator       : {latest_audit.operator}")
            print(f"    Execution Mode : {latest_audit.executionMode}")
            print(f"    Audit Success  : {latest_audit.success}")

            assert latest_audit.responseId == res_sim.responseId
            assert latest_audit.executionMode == "SIMULATION"
            assert latest_audit.success is True
            print("    [PASS] Tamper-evident audit entry captured and indexed.")

            # 6. Real-Time Store & WebSocket Synchronization
            print("\n[6/8] Auditing Real-Time WebSocket & Store Event Propagation...")
            store_state = realtime_store_engine.devices["WEB-01"].securityState
            last_msg = mock_ws.messages[-1]

            print(f"    Realtime Store WEB-01 State : {store_state}")
            print(f"    WebSocket Event Broadcasted  : {last_msg['envelope']['eventType']}")
            print(f"    WebSocket Payload Target     : {last_msg['envelope']['payload']['deviceId']}")

            assert store_state == "ISOLATED"
            assert last_msg["envelope"]["eventType"] == "DEVICE_STATE_UPDATE"
            assert last_msg["envelope"]["payload"]["newState"] == "ISOLATED"
            print("    [PASS] Real-time delta broadcasted to connected 2D/3D clients.")

            # 7. Validation Rejection on Unknown Target Device
            print("\n[7/8] Auditing Safety Rejection for Non-Existent Device...")
            rec_invalid_dev = ResponseRecommendation(
                actionType=ResponseActionType.ISOLATE_DEVICE,
                targetDeviceId="NON_EXISTENT_GHOST_MACHINE",
                confidenceScore=0.90,
                riskScore=90.0,
                reason="Ghost target test",
                triggeringAlertId="ALT-101",
                triggeringPredictionId="PRD-202",
                xaiExplanationSnippet="Invalid target."
            )
            res_invalid = await response_simulator.execute_simulated_response(rec_invalid_dev)
            assert res_invalid.status == ResponseStatusEnum.REJECTED
            assert "DEVICE_NOT_FOUND" in res_invalid.resultSummary
            print("    [PASS] Malformed target machine safely rejected.")

            # 8. Clean Restoration of Canonical Baseline
            print("\n[8/8] Restoring Clean Baseline State...")
            twin_graph_synchronizer._seed_default_twin_state()
            twin_graph_synchronizer.full_synchronization()
            device_3d_renderer_engine.sync_devices_from_twin()

            from frontend.realtime.realtime_event_manager import realtime_event_manager
            snap = realtime_event_manager.generate_full_twin_snapshot()
            realtime_store_engine.apply_snapshot(snap)
            assert attack_path_graph.nodes["WEB-01"].securityState in ("NORMAL", "AT_RISK")
            print("    [PASS] Clean baseline restored.")

        finally:
            await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 169 RESPONSE SIMULATION ARCHITECTURE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day169_suite()