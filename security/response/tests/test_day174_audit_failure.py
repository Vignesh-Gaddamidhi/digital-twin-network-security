import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.models.response import CanonicalResponseContract
from security.response.simulation.response_simulator import response_simulator
from security.response.engine.twin_state_mutation_engine import twin_state_mutation_engine
from security.response.audit.response_audit import response_audit_trail_engine, AuditFilterCriteria

class MockSocket:
    def __init__(self):
        self.messages = []
    async def accept(self):
        pass
    async def send_json(self, data):
        self.messages.append(data)
    async def close(self):
        pass

def run_day174_suite():
    print("=" * 80)
    print("       WEEK 25 - DAY 174: AUDIT TRAIL, RESPONSE HISTORY & FAILURE AUDIT")
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

            # 1. Forensic Audit Entry Schema Verification
            print("[1/6] Auditing Complete Forensic Audit Entry Fields...")
            rec = response_simulator.generate_recommendation_from_intelligence(
                device_id="WEB-01",
                risk_score=85.0,
                alert_id="ALT-20260916-888",
                prediction_id="PRD-20260916-999",
                category="LATERAL_MOVEMENT"
            )
            contract = response_simulator.create_canonical_response_contract(rec, operator="SOC_SENIOR_ANALYST")
            transition = await twin_state_mutation_engine.apply_response_to_twin_and_broadcast(contract)

            entry = response_audit_trail_engine.ledger[-1]
            print(f"    Audit ID          : {entry.auditId}")
            print(f"    Response ID       : {entry.responseId}")
            print(f"    Operator          : {entry.operator}")
            print(f"    Triggering Alert  : {entry.triggeringAlert}")
            print(f"    Triggering Pred   : {entry.triggeringPrediction}")
            print(f"    Risk Score        : {entry.riskScore} [{entry.riskLevel.value}]")
            print(f"    Twin Mutation     : {entry.previousState} -> {entry.newState}")

            assert entry.responseId == contract.responseId
            assert entry.operator == "SOC_SENIOR_ANALYST"
            assert entry.triggeringAlert == "ALT-20260916-888"
            assert entry.twinUpdated is True
            print("    [PASS] All forensic audit fields captured accurately.")

            # 2. Complete 9-Link Intelligence Lineage Reconstruction
            print("\n[2/6] Auditing Complete 9-Link Intelligence Chain Lineage...")
            chain = response_audit_trail_engine.get_full_intelligence_chain(contract.responseId)
            assert chain is not None
            for k, v in chain.items():
                print(f"    {k:<22}: {v}")

            assert chain["1_Alert"] == "ALT-20260916-888"
            assert chain["2_Prediction"] == "PRD-20260916-999"
            assert chain["6_RecommendedAction"] == "ISOLATE_DEVICE"
            assert chain["8_TwinUpdated"] is True
            print("    [PASS] Entire 9-stage intelligence lineage reconstructed.")

            # 3. Multi-Field History Filtering
            print("\n[3/6] Auditing Multi-Field Audit History Querying...")
            filter_device = AuditFilterCriteria(deviceId="WEB-01", action="ISOLATE_DEVICE")
            queried = response_audit_trail_engine.query_audit_history(filter_device)
            print(f"    Queried Records matching WEB-01 / ISOLATE_DEVICE: {len(queried)}")
            assert len(queried) >= 1
            assert queried[0].affectedDevice == "WEB-01"
            print("    [PASS] History multi-field filtering confirmed.")

            # 4. Duplicate Response Protection (Idempotency)
            print("\n[4/6] Auditing Duplicate Response Protection (Idempotency Invariant)...")
            dup_transition = await twin_state_mutation_engine.apply_response_to_twin_and_broadcast(contract)
            print(f"    Duplicate Flagged   : {dup_transition.isDuplicate}")
            print(f"    Resolution Reason   : {dup_transition.reason}")

            assert dup_transition.isDuplicate is True
            assert "DUPLICATE_RESPONSE_IGNORED" in dup_transition.reason
            print("    [PASS] Duplicate response blocked without corrupting state.")

            # 5. Partial-Failure Isolation (Twin Update != WebSocket Drop)
            print("\n[5/6] Auditing Partial-Failure Handling (Transport Drop Isolation)...")
            # Sever WebSocket connection
            await websocket_connection_manager.stop_all()

            rec2 = response_simulator.generate_recommendation_from_intelligence(
                device_id="DB-01",
                risk_score=78.0,
                alert_id="ALT-20260916-777",
                prediction_id="PRD-20260916-777",
                category="DATA_EXFILTRATION"
            )
            contract2 = response_simulator.create_canonical_response_contract(rec2)
            trans2 = await twin_state_mutation_engine.apply_response_to_twin_and_broadcast(contract2)

            db_twin_state = attack_path_graph.nodes["DB-01"].securityState
            print(f"    WebSocket Connected : {len(websocket_connection_manager.active_connections) > 0}")
            print(f"    Digital Twin State  : {db_twin_state} (Preserved)")

            assert db_twin_state == "ISOLATED"
            print("    [PASS] Twin state preserved despite WebSocket unavailability.")

            # 6. Failure Rejections Validation
            print("\n[6/6] Auditing Safety Rejections on Malformed Inputs...")
            rec_bad_dev = ResponseRecommendation(
                actionType=ResponseActionType.ISOLATE_DEVICE,
                targetDeviceId="NON_EXISTENT_GHOST_HOST",
                riskScore=90.0,
                alertId="ALT-000",
                predictionId="PRD-000"
            )
            c_bad = response_simulator.create_canonical_response_contract(rec_bad_dev)
            t_bad = await twin_state_mutation_engine.apply_response_to_twin_and_broadcast(c_bad)
            assert t_bad.newState == t_bad.previousState
            print("    [PASS] Non-existent device rejection handled safely.")

            # Restore clean baseline
            twin_graph_synchronizer._seed_default_twin_state()
            twin_graph_synchronizer.full_synchronization()

        finally:
            await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 174 AUDIT & FAILURE HANDLING TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day174_suite()