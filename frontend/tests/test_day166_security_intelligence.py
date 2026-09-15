import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.live_security_engine import (
    LiveSecurityIntelligenceEngine, EarlyWarningStateEnum, live_security_engine
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

def run_day166_suite():
    print("=" * 80)
    print("       WEEK 24 - DAY 166: LIVE SECURITY INTELLIGENCE AUDIT")
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

            # 1. Live Threat Update & Timeline Feed
            print("[1/9] Auditing Live Threat Update & Threat Timeline Streaming...")
            env_threat = await live_security_engine.emit_threat_update(
                source_device_id="ATTACKER-EXT",
                target_device_id="WEB-01",
                event_type="SQL_INJECTION_PROBE",
                severity=RiskLevelTier.HIGH
            )
            print(f"    Threat ID      : {env_threat.payload['threatId']}")
            print(f"    Event Type     : {env_threat.payload['eventType']}")
            print(f"    Stored Threats : {len(live_security_engine.threat_store)}")

            assert env_threat.eventType == RealtimeEventType.THREAT_UPDATE
            assert len(live_security_engine.threat_store) >= 1
            print("    [PASS] Threat update streamed and appended to threat timeline store.")

            # 2. Live Security Alert Generation
            print("\n[2/9] Auditing Live Security Alert Broadcasting...")
            env_alert = await live_security_engine.emit_alert_update(
                source_device="WEB-01",
                destination_device="DB-01",
                event_type="UNAUTHORIZED_LATERAL_DB_QUERY",
                severity=RiskLevelTier.CRITICAL,
                risk_score=88.0
            )
            print(f"    Alert ID       : {env_alert.payload['alertId']}")
            print(f"    Severity       : {env_alert.payload['severity']}")
            print(f"    Risk Score     : {env_alert.payload['riskScore']}")

            assert env_alert.eventType == RealtimeEventType.ALERT_UPDATE
            assert env_alert.payload["severity"] in ("CRITICAL", RiskLevelTier.CRITICAL.value)
            print("    [PASS] Alert stream broadcasts with standard metadata.")

            # 3. Live ML Prediction & Dual Horizon Decoupling (P_current vs P_future)
            print("\n[3/9] Auditing Live ML Prediction & P_current vs P_future Decoupling...")
            env_pred = await live_security_engine.emit_prediction_update(
                device_id="WEB-01",
                current_prob=0.42,
                future_prob=0.89,
                predicted_category="LATERAL_MOVEMENT"
            )
            pred_record = live_security_engine.prediction_store["WEB-01"]
            print(f"    P(current)     : {pred_record.currentThreatProbability}")
            print(f"    P(future)      : {pred_record.futureThreatProbability} (Forecasting horizon)")
            print(f"    Category       : {pred_record.predictedCategory}")

            assert pred_record.currentThreatProbability == 0.42
            assert pred_record.futureThreatProbability == 0.89
            assert pred_record.currentThreatProbability != pred_record.futureThreatProbability
            print("    [PASS] Current and future threat probabilities maintained as distinct metrics.")

            # 4. Early Warning Progression
            print("\n[4/9] Auditing Early Warning Progression & Lead-Time Broadcasts...")
            env_ew = await live_security_engine.emit_early_warning_update(
                device_id="WEB-01",
                lead_time_seconds=38,
                future_prob=0.91,
                warning_state=EarlyWarningStateEnum.HIGH_CONFIDENCE_WARNING
            )
            print(f"    Warning State  : {env_ew.payload['warningState']}")
            print(f"    Lead Time      : {env_ew.payload['leadTimeSeconds']}s")
            assert env_ew.eventType == RealtimeEventType.EARLY_WARNING_UPDATE
            assert env_ew.payload["warningState"] == "HIGH_CONFIDENCE_WARNING"
            print("    [PASS] Early warning state transitions stream accurately.")

            # 5. Canonical Risk Formula Calculation: P(threat) * Criticality * Vuln * Impact
            print("\n[5/9] Auditing Canonical Risk Engine Formula Calculation...")
            env_risk = await live_security_engine.update_device_risk(
                device_id="WEB-01",
                threat_prob=0.88,
                criticality=1.0,
                vulnerability_factor=0.8,
                impact=1.0
            )
            print(f"    Computed Risk  : {env_risk.payload['compositeRiskScore']} [{env_risk.payload['riskLevel']}]")
            assert env_risk.payload["compositeRiskScore"] == 70.4
            assert env_risk.payload["riskLevel"] in ("HIGH", RiskLevelTier.HIGH.value)
            print("    [PASS] Canonical P * C * V * I risk formula verified.")

            # 6. 2D and 3D View Synchronization under Risk Shift
            print("\n[6/9] Auditing 2D/3D Synchronization under Risk Score Updates...")
            twin_risk = attack_path_graph.nodes["WEB-01"].riskScore
            mesh_label_risk = device_3d_renderer_engine.device_mesh_registry["WEB-01"].label.riskScore
            print(f"    Twin Graph Risk: {twin_risk}")
            print(f"    3D Label Risk  : {mesh_label_risk}")

            assert twin_risk == 70.4
            assert mesh_label_risk == 70.4
            print("    [PASS] Twin graph risk and 3D mesh billboard labels synchronized.")

            # 7. Live Attack Path Highlighting & 3D Illumination
            print("\n[7/9] Auditing Attack Path Traversal Highlighting & 3D Spline Glow...")
            env_path = await live_security_engine.trigger_live_attack_path_highlight()
            print(f"    Selected Path  : {env_path.payload['pathId']}")
            print(f"    Traversal Path : {' -> '.join(env_path.payload['nodeSequence'])}")

            assert env_path.eventType == RealtimeEventType.ATTACK_PATH_UPDATE
            assert device_3d_renderer_engine.device_mesh_registry["WEB-01"].isHighlighted is True
            assert device_3d_renderer_engine.device_mesh_registry["DB-01"].isHighlighted is True
            print("    [PASS] Traversed nodes and spline links illuminated in 3D scene.")

            # 8. SHAP XAI Explanation Propagation
            print("\n[8/9] Auditing SHAP XAI Explanation Features...")
            features = pred_record.xaiExplanations
            print(f"    Top Feature 1  : {features[0]}")
            print(f"    Top Feature 2  : {features[1]}")
            assert len(features) >= 3
            print("    [PASS] SHAP explainability bullets mapped to device prediction state.")

            # 9. Monotonic Sequence Ordering Continuity
            print("\n[9/9] Auditing Monotonic Sequence Continuity across All Emitted Frames...")
            all_seqs = [msg["envelope"]["sequenceNumber"] for msg in mock_ws.messages if msg.get("type") == "EVENT"]
            print(f"    Emitted Sequence Sample: {all_seqs[:8]} ... (Total: {len(all_seqs)})")
            for i in range(len(all_seqs) - 1):
                assert all_seqs[i + 1] == all_seqs[i] + 1
            print("    [PASS] Strictly monotonic sequence ordering confirmed.")

        finally:
            # Clean teardown guaranteed even if assertions fail
            await websocket_connection_manager.stop_all()

    try:
        loop.run_until_complete(test_body())
    finally:
        loop.close()

    print("\n" + "=" * 80)
    print("       ALL DAY 166 LIVE SECURITY INTELLIGENCE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day166_suite()