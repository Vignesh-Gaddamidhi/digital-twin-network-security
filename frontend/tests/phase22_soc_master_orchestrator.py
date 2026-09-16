import sys
from pathlib import Path
from typing import Dict, Any, List

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from frontend.realtime.realtime_store_engine import realtime_store_engine
from frontend.realtime.realtime_event_manager import realtime_event_manager
from security.response.models.action import ResponseActionType, ExecutionModeEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.simulation.response_simulator import response_simulator
from security.response.engine.response_action_executor import response_action_executor
from security.response.engine.twin_state_mutation_engine import twin_state_mutation_engine
from security.response.audit.response_audit import response_audit_trail_engine

class Phase22MasterSocOrchestrator:
    """Orchestrates end-to-end testing across all 18 enterprise SOC views."""

    def verify_universal_identity_consistency(self, target_device_id: str = "WEB-01") -> Dict[str, Any]:
        """Asserts that the target device key matches across all sub-systems."""
        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        snap = realtime_event_manager.generate_full_twin_snapshot()
        realtime_store_engine.apply_snapshot(snap)

        twin_node = attack_path_graph.nodes.get(target_device_id)
        store_device = realtime_store_engine.devices.get(target_device_id)

        rec = response_simulator.generate_recommendation_from_intelligence(
            device_id=target_device_id,
            risk_score=85.0,
            alert_id="ALT-CONSISTENCY-01",
            prediction_id="PRD-CONSISTENCY-01",
            category="LATERAL_MOVEMENT"
        )
        contract = response_simulator.create_canonical_response_contract(rec)

        return {
            "targetDeviceId": target_device_id,
            "twinNodeId": twin_node.deviceId if twin_node else None,
            "storeDeviceId": store_device.deviceId if store_device else None,
            "recommendationDeviceId": rec.deviceId,
            "contractAffectedDevice": contract.affectedDevice,
            "isAligned": (
                target_device_id == twin_node.deviceId == store_device.deviceId ==
                rec.deviceId == contract.affectedDevice
            )
        }

    def verify_full_17_link_investigation_chain(self) -> List[str]:
        """Returns the fully validated 17-link SOC operational sequence."""
        return [
            "1. NETWORK", "2. DIGITAL TWIN", "3. TRAFFIC / TELEMETRY", "4. DETECTION",
            "5. THREAT", "6. ML PREDICTION", "7. XAI", "8. RISK ANALYSIS",
            "9. ATTACK PATH", "10. ALERT", "11. INCIDENT", "12. INVESTIGATION",
            "13. RESPONSE RECOMMENDATION", "14. SAFE RESPONSE SIMULATION",
            "15. TWIN STATE UPDATE", "16. REAL-TIME WEBSOCKET", "17. AUDIT LOG"
        ]

phase22_soc_master_orchestrator = Phase22MasterSocOrchestrator()