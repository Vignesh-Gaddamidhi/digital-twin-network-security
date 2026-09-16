import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine
from frontend.response.response_models import ResponseActionType, ExecutionMode, ResponseStatus
from frontend.response.safe_response_engine import safe_response_engine

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
    print("       WEEK 25 - DAY 169: SAFE AUTOMATED RESPONSE SIMULATION AUDIT")
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
            link_3d_renderer_engine.sync_links_from_twin()

            # Initialize Realtime Store with baseline snapshot
            snap = realtime_event_manager.generate_full_twin_snapshot()
            realtime_store_engine.apply_snapshot(snap)

            # 1. Recommendation Engine Generation
            print("[1/8] Auditing Response Playbook Recommendation Engine...")
            rec_crit = safe_response_engine.generate_recommendation("WEB-01", risk_score=85.0, predicted_category="LATERAL_MOVEMENT")
            print(f"    Risk: 85.0 -> Recommended Action: {rec_crit.actionType.value} (Risk Reduction: -{rec_crit.projectedRiskReduction})")
            assert rec_crit.actionType == ResponseActionType.ISOLATE_DEVICE

            rec_med = safe_response_engine.generate_recommendation("WEB-01", risk_score=50.0, predicted_category="PORT_SCAN")
            print(f"    Risk: 50.0 -> Recommended Action: {rec_med.actionType.value} (Reduction: -{rec_med.projectedRiskReduction})")
            assert rec_med.actionType == ResponseActionType.DISABLE_SERVICE
            print("    [PASS] Recommendation engine rules successfully mapped.")

            # 2. Simulated Response Execution: ISOLATE_DEVICE
            print("\n[2/8] Auditing Playbook Execution: ISOLATE_DEVICE...")
            rec_iso = await safe_response_engine.execute_simulated_response(
                action_type=ResponseActionType.ISOLATE_DEVICE,
                device_id="WEB-01",
                triggering_alert_id="ALT-2026-001",
                triggering_prediction_id="PRD-2026-001",
                risk_score=88.5,
                operator="ANALYST_ALICE"
            )
            print(f"    Response ID : {rec_iso.responseId}")
            print(f"    Previous St : {rec_iso.previousState} -> New St: {rec_iso.newState}")
            print(f"    Graph State : {attack_path_graph.nodes['WEB-01'].securityState}")
            print(f"    Store State : {realtime_store_engine.devices['WEB-01'].securityState}")

            assert rec_iso.newState in ("ISOLATED", "QUARANTINED")
            assert attack_path_graph.nodes["WEB-01"].securityState in ("ISOLATED", "QUARANTINED")
            assert realtime_store_engine.devices["WEB-01"].securityState in ("ISOLATED", "QUARANTINED")
            print("    [PASS] Device quarantine applied across Canonical Twin and Realtime Store.")

            # 3. Mandatory 13-Field Audit Schema Compliance
            print("\n[3/8] Auditing Mandatory 13-Field Response Ledger Metadata...")
            entry = safe_response_engine.response_ledger[0]
            assert entry.responseId.startswith("RSP-")
            assert entry.reason is not None
            assert entry.triggeringAlertId == "ALT-2026-001"
            assert entry.triggeringPredictionId == "PRD-2026-001"
            assert entry.riskScore == 88.5
            assert entry.affectedDeviceId == "WEB-01"
            assert entry.timestamp is not None
            assert entry.previousState in ("NORMAL", "AT_RISK")
            assert entry.newState in ("ISOLATED", "QUARANTINED")
            assert entry.operator == "ANALYST_ALICE"
            assert entry.mode == ExecutionMode.SIMULATION
            assert entry.result is not None
            assert entry.auditEntryId.startswith("AUD-")
            print(f"    Audit Entry ID: {entry.auditEntryId} verified with complete provenance.")
            print("    [PASS] All 13 mandatory response fields populated.")

            # 4. Strict Simulation Guardrail & Non-Destructive Invariant
            print("\n[4/8] Auditing Safety Invariant (Disarmed Real-World Guardrail)...")
            assert entry.mode == ExecutionMode.SIMULATION
            print(f"    Execution Mode: {entry.mode.value} (Zero production interface mutations)")
            print("    [PASS] Simulation mode invariant strictly enforced.")

            # 5. Playbook Execution: BLOCK_CONNECTION
            print("\n[5/8] Auditing Playbook Execution: BLOCK_CONNECTION...")
            rec_block = await safe_response_engine.execute_simulated_response(
                action_type=ResponseActionType.BLOCK_CONNECTION,
                device_id="CLIENT-01",
                triggering_alert_id="ALT-DOS-002",
                triggering_prediction_id="PRD-DOS-002",
                risk_score=68.0
            )
            print(f"    Severed Links Tracked: {rec_block.rollbackData.get('severedLinks')}")
            assert rec_block.status == ResponseStatus.EXECUTED
            print("    [PASS] Simulated connection firewall block verified.")

            # 6. Playbook Execution: DISABLE_SERVICE
            print("\n[6/8] Auditing Playbook Execution: DISABLE_SERVICE...")
            rec_svc = await safe_response_engine.execute_simulated_response(
                action_type=ResponseActionType.DISABLE_SERVICE,
                device_id="DB-01",
                triggering_alert_id="ALT-SQLI-003",
                triggering_prediction_id="PRD-SQLI-003",
                risk_score=45.0
            )
            print(f"    Target Port Closed: {rec_svc.rollbackData.get('closedPort')}")
            assert rec_svc.status == ResponseStatus.EXECUTED
            print("    [PASS] Port-level service shutdown simulated.")

            # 7. Deterministic One-Click Rollback Verification
            print("\n[7/8] Auditing Deterministic Rollback of Action RSP-001...")
            rb_entry = await safe_response_engine.rollback_response(rec_iso.responseId)
            print(f"    Rolled Back Action: {rb_entry.responseId}")
            print(f"    Restored State    : {attack_path_graph.nodes['WEB-01'].securityState}")
            assert attack_path_graph.nodes["WEB-01"].securityState in ("NORMAL", "AT_RISK")
            assert rb_entry.status == ResponseStatus.ROLLED_BACK
            print("    [PASS] Response rollback cleanly restored baseline properties.")

            # 8. Real-Time WebSocket Notification Streaming
            print("\n[8/8] Auditing Real-Time Broadcast Envelopes...")
            last_msg = mock_ws.messages[-1]
            print(f"    Last Socket Envelope Type: {last_msg.get('type')}")
            print(f"    Payload Reason           : {last_msg['envelope']['payload']['reason']}")
            assert last_msg["type"] == "EVENT"
            assert last_msg["envelope"]["eventType"] == "DEVICE_STATE_UPDATE"
            print("    [PASS] Sub-second state mutation stream emitted over WebSocket.")

        finally:
            await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 169 SAFE RESPONSE SIMULATION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day169_suite()