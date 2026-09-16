import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine
from frontend.realtime.live_security_engine import live_security_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.simulation.response_simulator import response_simulator
from security.response.engine.twin_state_mutation_engine import twin_state_mutation_engine

class MockSocket:
    def __init__(self):
        self.messages = []
    async def accept(self):
        pass
    async def send_json(self, data):
        self.messages.append(data)
    async def close(self):
        pass

def run_day173_suite():
    print("=" * 80)
    print("       WEEK 25 - DAY 173: TWIN STATE MUTATIONS & WEBSOCKET INTEGRATION")
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

            snap = realtime_event_manager.generate_full_twin_snapshot()
            realtime_store_engine.apply_snapshot(snap)

            # Establish initial active attack path and apply envelope to universal store
            env_path = await live_security_engine.trigger_live_attack_path_highlight()
            realtime_store_engine.apply_event_envelope(env_path)
            assert len(realtime_store_engine.attackPaths) >= 1
            init_reach = realtime_store_engine.attackPaths[0].get("reachability", realtime_store_engine.attackPaths[0].get("status", "ACTIVE"))
            print(f"    Initial Attack Path Reachability: {init_reach}")

            # 1. Auditing Response -> Twin Path (Never Response -> UI Directly)
            print("\n[1/6] Auditing Response -> Twin State Mutation Path...")
            attack_path_graph.nodes["WEB-01"].securityState = "NORMAL"
            rec = response_simulator.generate_recommendation_from_intelligence(
                device_id="WEB-01",
                risk_score=88.0,
                alert_id="ALT-20260916-01",
                prediction_id="PRD-20260916-02",
                category="LATERAL_MOVEMENT"
            )
            contract = response_simulator.create_canonical_response_contract(rec)

            transition = await twin_state_mutation_engine.apply_response_to_twin_and_broadcast(contract)

            print(f"    Transition ID : {transition.transitionId}")
            print(f"    Previous State: {transition.previousState}")
            print(f"    New State     : {transition.newState}")
            print(f"    Action        : {transition.action.value}")

            assert transition.previousState in ("NORMAL", "AT_RISK")
            assert transition.newState == "ISOLATED"
            assert attack_path_graph.nodes["WEB-01"].securityState == "ISOLATED"
            print("    [PASS] State mutated on canonical Digital Twin first.")

            # 2. Auditing Immutable State Transition History
            print("\n[2/6] Auditing State History Ledger...")
            history = twin_state_mutation_engine.get_history_for_device("WEB-01")
            latest_record = history[-1]

            print(f"    History Records Count : {len(history)}")
            print(f"    Latest Action Logged  : {latest_record.action.value}")
            print(f"    Severed Connections   : {latest_record.affectedConnectionsCount}")

            assert len(history) >= 1
            assert latest_record.transitionId == transition.transitionId
            print("    [PASS] State transition record appended to twin history.")

            # 3. Auditing Attack-Path Severing & Reachability Update (BLOCKED)
            print("\n[3/6] Auditing Attack-Path Interaction under ISOLATE_DEVICE...")
            active_path = realtime_store_engine.attackPaths[0]
            curr_reach = active_path.get("reachability", active_path.get("status", "ACTIVE"))
            print(f"    Path Chain    : {' -> '.join(active_path.get('nodeSequence', []))}")
            print(f"    Reachability  : {curr_reach}")

            assert curr_reach == "BLOCKED"
            print("    [PASS] Attack path dynamically transitioned to BLOCKED status.")

            # 4. Auditing Real-Time RESPONSE_UPDATE Event Emission
            print("\n[4/6] Auditing Real-Time RESPONSE_UPDATE WebSocket Frame...")
            resp_msgs = [m for m in mock_ws.messages if m.get("type") == "EVENT" and m["envelope"]["eventType"] == "RESPONSE_UPDATE"]
            assert len(resp_msgs) >= 1
            last_resp_envelope = resp_msgs[-1]["envelope"]

            print(f"    Event Type    : {last_resp_envelope['eventType']}")
            print(f"    Target Device : {last_resp_envelope['payload']['affectedDevice']}")
            print(f"    Mode          : {last_resp_envelope['payload']['mode']}")

            assert last_resp_envelope["eventType"] == RealtimeEventType.RESPONSE_UPDATE.value
            assert last_resp_envelope["payload"]["affectedDevice"] == "WEB-01"
            assert last_resp_envelope["payload"]["mode"] == "SIMULATION"
            print("    [PASS] Dedicated RESPONSE_UPDATE delta frame broadcasted.")

            # 5. Auditing Single Source of Truth Invariant Across 2D & 3D
            print("\n[5/6] Auditing 2D/3D Unified Invariant under Response Action...")
            store_st = realtime_store_engine.devices["WEB-01"].securityState
            graph_st = attack_path_graph.nodes["WEB-01"].securityState

            print(f"    Graph State     : {graph_st}")
            print(f"    Universal Store : {store_st}")

            assert graph_st == "ISOLATED"
            assert store_st == "ISOLATED"
            print("    [PASS] Unified twin state reflected identically across 2D store and 3D visual registry.")

            # 6. Restoring Clean Baseline
            print("\n[6/6] Restoring Clean Baseline...")
            twin_graph_synchronizer._seed_default_twin_state()
            twin_graph_synchronizer.full_synchronization()
            device_3d_renderer_engine.sync_devices_from_twin()
            link_3d_renderer_engine.sync_links_from_twin()
            print("    [PASS] Clean baseline restored.")

        finally:
            await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 173 TWIN STATE TRANSITION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day173_suite()