import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine
from security.response.models.action import ResponseActionType, ExecutionModeEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.simulation.response_simulator import response_simulator
from security.response.engine.response_action_executor import response_action_executor
from security.response.engine.twin_state_mutation_engine import twin_state_mutation_engine
from security.response.audit.response_audit import response_audit_trail_engine
from security.response.engine.phase21_graduation_orchestrator import phase21_graduation_orchestrator

class MockSocket:
    def __init__(self):
        self.messages = []
    async def accept(self):
        pass
    async def send_json(self, data):
        self.messages.append(data)
    async def close(self):
        pass

def run_day175_suite():
    print("=" * 80)
    print("       WEEK 25 - DAY 175: MASTER RESPONSE SIMULATION INTEGRATION AUDIT")
    print("================================================================================\n")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def test_body():
        mock_ws = MockSocket()
        await websocket_connection_manager.connect(mock_ws)

        try:
            # 1. Full Closed-Loop Execution
            print("[1/6] Auditing Complete Threat -> ML -> Risk -> Response -> Twin -> Audit Closed Loop...")
            res = await phase21_graduation_orchestrator.run_complete_closed_loop_pipeline()

            print(f"    Threat ID Logged         : {res['threatId']}")
            print(f"    Dynamic Risk Score       : {res['riskScore']}")
            print(f"    Recommended Action       : {res['recommendedAction']}")
            print(f"    Simulated Action         : {res['simulatedAction']}")
            print(f"    Isolated State (Twin)    : {res['isolatedState']}")
            print(f"    Isolated State (Store)   : {res['storeState']}")
            print(f"    Attack Path Status       : {res['attackPathStatus']}")
            print(f"    Controlled Recovery State: {res['recoveredState']}")
            print(f"    Audit Entry Captured     : {res['auditId']}")

            assert res["isolatedState"] == "ISOLATED"
            assert res["storeState"] == "ISOLATED"
            assert res["attackPathStatus"] == "BLOCKED"
            assert res["recoveredState"] == "MONITORED"
            assert res["lineageComplete"] is True
            print("    [PASS] Full closed-loop response simulation completed successfully.")

            # 2. Complete Six-Action Execution Matrix
            print("\n[2/6] Auditing Complete Six-Action Execution Matrix...")
            actions = [
                response_action_executor.execute_isolate_device("WEB-01"),
                response_action_executor.execute_block_connection("CLIENT-01", "WEB-01"),
                response_action_executor.execute_disable_service("WEB-01", "HTTP"),
                response_action_executor.execute_quarantine_endpoint("CLIENT-01"),
                response_action_executor.execute_increase_security_level("DB-01"),
                response_action_executor.execute_mark_device_at_risk("DNS-SERVER-01")
            ]
            for act in actions:
                print(f"    Action: {act.actionType.value:<24} | Success: {act.success} | Result State: {act.newState}")
                assert act.success is True
            print("    [PASS] All six defensive response actions verified.")

            # 3. Hard Safety Boundary Enforcement (REAL Mode Blocked)
            print("\n[3/6] Auditing Hard Safety Boundary Invariant (REAL Mode Blocked)...")
            rec_real = ResponseRecommendation(
                actionType=ResponseActionType.ISOLATE_DEVICE,
                recommendedAction=ResponseActionType.ISOLATE_DEVICE,
                deviceId="WEB-01",
                targetDeviceId="WEB-01",
                riskScore=90.0,
                alertId="ALT-REAL",
                predictionId="PRD-REAL"
            )
            res_blocked = await response_simulator.execute_simulated_response(
                recommendation=rec_real,
                execution_mode=ExecutionModeEnum.REAL,
                operator="MALICIOUS_LIVE_TRIGGER"
            )
            print(f"    Attempted Mode : {res_blocked.mode.value}")
            print(f"    Status Result  : {res_blocked.status.value}")
            print(f"    Safety Message : {res_blocked.result.message}")

            assert res_blocked.status.value == "REJECTED"
            assert "SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED" in res_blocked.result.message
            print("    [PASS] Real-mode network modification rejected by safety validator.")

            # 4. Partial-Failure Resilience & Reconnection Snapshot Alignment
            print("\n[4/6] Auditing Partial-Failure Isolation (Twin Preserved on WebSocket Drop)...")
            await websocket_connection_manager.stop_all()

            if "WEB-01" in attack_path_graph.nodes:
                attack_path_graph.nodes["WEB-01"].securityState = "NORMAL"

            rec_fail = ResponseRecommendation(
                actionType=ResponseActionType.ISOLATE_DEVICE,
                recommendedAction=ResponseActionType.ISOLATE_DEVICE,
                deviceId="WEB-01",
                targetDeviceId="WEB-01",
                riskScore=80.0,
                alertId="ALT-DROP",
                predictionId="PRD-DROP"
            )
            c_fail = response_simulator.create_canonical_response_contract(rec_fail)
            t_fail = await twin_state_mutation_engine.apply_response_to_twin_and_broadcast(c_fail)

            print(f"    WebSocket Status   : DISCONNECTED")
            print(f"    Digital Twin State : {attack_path_graph.nodes['WEB-01'].securityState} (Preserved)")
            assert attack_path_graph.nodes["WEB-01"].securityState == "ISOLATED"
            print("    [PASS] Transport drops do not roll back legitimate Twin security states.")

            # 5. Pipeline Latency Profiling
            print("\n[5/6] Auditing Pipeline Processing Latency Benchmarks...")
            perf = phase21_graduation_orchestrator.profile_response_pipeline_latencies()
            for k, v in perf.items():
                print(f"    {k:<28}: {v} ms")

            assert perf["totalClosedLoopLatencyMs"] < 100.0
            print(f"    [PASS] Total Closed Loop Latency: {perf['totalClosedLoopLatencyMs']} ms (< 100ms SLA).")

            # 6. Clean Baseline Restoration
            print("\n[6/6] Restoring Clean Baseline State...")
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
    print("       ALL DAY 175 MASTER RESPONSE INTEGRATION TESTS PASSED CLEANLY")
    print("       PHASE 21 GRADUATED SUCCESSFULLY — READY FOR WEEK 25 MILESTONE TAG")
    print("================================================================================")

if __name__ == "__main__":
    run_day175_suite()