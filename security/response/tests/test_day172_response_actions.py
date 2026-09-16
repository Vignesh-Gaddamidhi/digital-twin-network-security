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
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine

from security.response.models.action import ResponseActionType
from security.response.engine.response_action_executor import (
    ResponseActionExecutor, SecurityPostureLevelEnum, response_action_executor
)

class MockSocket:
    def __init__(self):
        self.messages = []
    async def accept(self):
        pass
    async def send_json(self, data):
        self.messages.append(data)
    async def close(self):
        pass

def run_day172_suite():
    print("=" * 80)
    print("       WEEK 25 - DAY 172: ALL SIX SIMULATED RESPONSE ACTIONS AUDIT")
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

            # 1. Test ISOLATE_DEVICE
            print("[1/7] Auditing Action 1: ISOLATE_DEVICE...")
            attack_path_graph.nodes["WEB-01"].securityState = "NORMAL"
            res_iso = response_action_executor.execute_isolate_device("WEB-01")

            print(f"    Target Device  : {res_iso.targetDeviceId}")
            print(f"    State Change   : {res_iso.previousState} -> {res_iso.newState}")
            print(f"    Blocked Edges  : {len(res_iso.details['blockedConnections'])}")

            assert res_iso.success is True
            assert res_iso.newState == "ISOLATED"
            assert attack_path_graph.nodes["WEB-01"].securityState == "ISOLATED"
            assert len(res_iso.details["blockedConnections"]) >= 1
            print("    [PASS] ISOLATE_DEVICE mutated Twin node and severed connections.")

            # 2. Test BLOCK_CONNECTION
            print("\n[2/7] Auditing Action 2: BLOCK_CONNECTION...")
            res_block = response_action_executor.execute_block_connection("CLIENT-01", "WEB-01")

            print(f"    Target Link    : {res_block.details['linkId']}")
            print(f"    Link State     : {res_block.newState}")

            assert res_block.success is True
            assert res_block.newState == "BLOCKED"
            target_lid = res_block.details["linkId"]
            assert link_3d_renderer_engine.link_registry[target_lid].status == "BLOCKED"
            print("    [PASS] BLOCK_CONNECTION blocked traffic link on Twin topology.")

            # 3. Test DISABLE_SERVICE
            print("\n[3/7] Auditing Action 3: DISABLE_SERVICE...")
            res_svc = response_action_executor.execute_disable_service("WEB-01", "HTTP")

            print(f"    Service Name   : {res_svc.details['serviceName']}")
            print(f"    Port Disabled  : {res_svc.details['port']}")
            print(f"    Service Status : {res_svc.newState}")

            assert res_svc.success is True
            assert res_svc.newState == "DISABLED"
            web_node = attack_path_graph.nodes["WEB-01"]
            ports_list = getattr(web_node, "ports", getattr(web_node, "openPorts", []))
            assert 80 not in ports_list
            print("    [PASS] DISABLE_SERVICE shut down target port on Twin node.")

            # 4. Test QUARANTINE_ENDPOINT
            print("\n[4/7] Auditing Action 4: QUARANTINE_ENDPOINT...")
            attack_path_graph.nodes["CLIENT-01"].securityState = "NORMAL"
            res_quar = response_action_executor.execute_quarantine_endpoint("CLIENT-01")

            print(f"    Endpoint Target: {res_quar.targetDeviceId}")
            print(f"    VLAN Enforced  : {res_quar.details['restrictedVLAN']}")
            print(f"    State Change   : {res_quar.previousState} -> {res_quar.newState}")

            assert res_quar.success is True
            assert res_quar.newState == "QUARANTINED"
            assert attack_path_graph.nodes["CLIENT-01"].securityState == "QUARANTINED"
            print("    [PASS] QUARANTINE_ENDPOINT isolated workstation to quarantine zone.")

            # 5. Test INCREASE_SECURITY_LEVEL
            print("\n[5/7] Auditing Action 5: INCREASE_SECURITY_LEVEL...")
            res_sec = response_action_executor.execute_increase_security_level(
                "DB-01", SecurityPostureLevelEnum.HIGH
            )

            print(f"    Target Host    : {res_sec.targetDeviceId}")
            print(f"    Posture Shift  : {res_sec.previousState} -> {res_sec.newState}")

            assert res_sec.success is True
            assert res_sec.newState == "HIGH"
            assert attack_path_graph.nodes["DB-01"].securityState == "MONITORED"
            print("    [PASS] INCREASE_SECURITY_LEVEL elevated defensive sampling posture.")

            # 6. Test MARK_DEVICE_AT_RISK (Prediction != Compromised invariant)
            print("\n[6/7] Auditing Action 6: MARK_DEVICE_AT_RISK...")
            attack_path_graph.nodes["DNS-SERVER-01"].securityState = "NORMAL"
            res_risk = response_action_executor.execute_mark_device_at_risk("DNS-SERVER-01")

            print(f"    Target Host    : {res_risk.targetDeviceId}")
            print(f"    Tagged State   : {res_risk.newState}")
            print(f"    Is Compromised : {res_risk.details['isCompromised']} (Strictly False)")

            assert res_risk.success is True
            assert res_risk.newState == "AT_RISK"
            assert res_risk.details["isCompromised"] is False
            assert attack_path_graph.nodes["DNS-SERVER-01"].securityState == "AT_RISK"
            print("    [PASS] MARK_DEVICE_AT_RISK confirmed distinct from COMPROMISED.")

            # 7. Auditing Invalid Operations Validation
            print("\n[7/7] Auditing Validation on Invalid Operations...")
            res_inv_dev = response_action_executor.execute_isolate_device("UNKNOWN_GHOST_HOST")
            res_inv_svc = response_action_executor.execute_disable_service("WEB-01", "NON_EXISTENT_ORACLE_DB")

            print(f"    Ghost Device Result : success={res_inv_dev.success} ({res_inv_dev.message})")
            print(f"    Ghost Service Result: success={res_inv_svc.success} ({res_inv_svc.message})")

            assert res_inv_dev.success is False
            assert res_inv_svc.success is False
            print("    [PASS] Invalid devices and services rejected safely without crashes.")

            # Clean baseline restore
            twin_graph_synchronizer._seed_default_twin_state()
            twin_graph_synchronizer.full_synchronization()

        finally:
            await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 172 RESPONSE ACTION EXECUTION TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day172_suite()