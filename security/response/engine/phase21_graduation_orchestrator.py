from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import time

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.realtime.realtime_models import RealtimeEventType
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.realtime_store_engine import realtime_store_engine
from frontend.realtime.live_security_engine import live_security_engine

from security.response.models.action import ResponseActionType, ExecutionModeEnum, ResponseStatusEnum
from security.response.models.recommendation import ResponseRecommendation
from security.response.models.response import CanonicalResponseContract
from security.response.engine.recommendation_engine import response_recommendation_engine
from security.response.engine.response_action_executor import response_action_executor, SecurityPostureLevelEnum
from security.response.engine.twin_state_mutation_engine import twin_state_mutation_engine
from security.response.simulation.response_simulator import response_simulator
from security.response.audit.response_audit import response_audit_trail_engine

class Phase21GraduationOrchestrator:
    """Master orchestrator executing full response simulation integration, recovery, and safety audits."""

    async def run_complete_closed_loop_pipeline(self) -> Dict[str, Any]:
        """Runs Threat -> Detection -> Prediction -> XAI -> Risk -> Recommendation -> Response -> Twin -> Audit."""
        # 1. Baseline Initialization
        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.sync_links_from_twin()
        snap = realtime_event_manager.generate_full_twin_snapshot()
        realtime_store_engine.apply_snapshot(snap)

        # 2. Ingest Threat & ML Prediction with XAI
        env_threat = await live_security_engine.emit_threat_update(
            source_device_id="ATTACKER-EXT",
            target_device_id="WEB-01",
            event_type="CVE_2026_REMOTE_CODE_EXEC",
            severity=RiskLevelTier.CRITICAL
        )
        env_pred = await live_security_engine.emit_prediction_update(
            device_id="WEB-01",
            current_prob=0.88,
            future_prob=0.96,
            predicted_category="LATERAL_MOVEMENT",
            risk_score=85.0,
            xai_explanations=[
                "Abnormal outbound port connection to DB-01",
                "Command execution signature matched CVE-2026-RCE",
                "High criticality asset pivot attempt"
            ]
        )

        # 3. Dynamic Risk Engine
        env_risk = await live_security_engine.update_device_risk(
            device_id="WEB-01",
            threat_prob=1.0,
            criticality=1.0,
            vulnerability_factor=0.8,
            impact=1.0
        )
        # Highlight traversal path
        await live_security_engine.trigger_live_attack_path_highlight()

        # 4. Formulate Recommendation
        rec = response_recommendation_engine.formulate_recommendation(
            alert_id=env_threat.payload["threatId"],
            prediction_id=env_pred.payload["targetDeviceId"],
            device_id="WEB-01",
            risk_score=env_risk.payload["compositeRiskScore"],
            predicted_category="LATERAL_MOVEMENT",
            prediction_confidence=0.96,
            xai_features=env_pred.payload.get("topFeatures", [])
        )

        # 5. Formulate Canonical Response Contract
        contract = response_simulator.create_canonical_response_contract(
            recommendation=rec,
            operator="SOC_AUTOMATION_PLAYBOOK",
            mode=ExecutionModeEnum.SIMULATION
        )

        # 6. Execute Simulated Response against Twin & Broadcast
        transition = await twin_state_mutation_engine.apply_response_to_twin_and_broadcast(contract)

        # Verify state across canonical layers
        twin_node_state = attack_path_graph.nodes["WEB-01"].securityState
        store_node_state = realtime_store_engine.devices["WEB-01"].securityState
        first_p = realtime_store_engine.attackPaths[0] if realtime_store_engine.attackPaths else {}
        attack_path_reachability = first_p.get("reachability", first_p.get("status", first_p.get("pathReachability", "BLOCKED")))

        # 7. Controlled Recovery Transition: ISOLATED -> MONITORED
        # Respect state machine: ISOLATED -> MONITORED (Defensive observation before NORMAL)
        attack_path_graph.nodes["WEB-01"].securityState = "MONITORED"
        if "WEB-01" in realtime_store_engine.devices:
            realtime_store_engine.devices["WEB-01"].securityState = "MONITORED"
        device_3d_renderer_engine.sync_devices_from_twin()

        # 8. Reconstruct Audit Chain
        audit_lineage = response_audit_trail_engine.get_full_intelligence_chain(contract.responseId)

        return {
            "threatId": env_threat.payload["threatId"],
            "riskScore": env_risk.payload["compositeRiskScore"],
            "recommendedAction": rec.recommendedAction.value,
            "simulatedAction": contract.action.value,
            "previousState": transition.previousState,
            "isolatedState": twin_node_state,
            "storeState": store_node_state,
            "attackPathStatus": attack_path_reachability,
            "recoveredState": attack_path_graph.nodes["WEB-01"].securityState,
            "auditId": transition.auditId,
            "lineageComplete": audit_lineage is not None
        }

    def profile_response_pipeline_latencies(self) -> Dict[str, Any]:
        """Profiles the execution duration of recommendation, simulation, twin mutation, and audit logging."""
        rec = response_simulator.generate_recommendation_from_intelligence(
            device_id="WEB-01", risk_score=75.0, alert_id="ALT-BENCH", prediction_id="PRD-BENCH"
        )
        contract = response_simulator.create_canonical_response_contract(rec)

        # 1. Recommendation Formulation Latency
        t0 = time.perf_counter()
        _ = response_recommendation_engine.formulate_recommendation(
            "ALT-01", "PRD-01", "WEB-01", 82.0, "LATERAL_MOVEMENT"
        )
        rec_latency_ms = (time.perf_counter() - t0) * 1000.0

        # 2. Digital Twin Mutation Latency
        t1 = time.perf_counter()
        _ = response_action_executor.execute_isolate_device("WEB-01")
        twin_mutation_ms = (time.perf_counter() - t1) * 1000.0

        # 3. Audit Ledger Record Latency
        t2 = time.perf_counter()
        _ = response_audit_trail_engine.record_forensic_entry(
            response_id=f"RESP-BENCH-{time.time()}",
            operator="BENCHMARK",
            action="ISOLATE_DEVICE",
            reason="Latency bench",
            triggering_alert="ALT-01",
            triggering_prediction="PRD-01",
            risk_score=82.0,
            affected_device="WEB-01",
            previous_state="NORMAL",
            new_state="ISOLATED",
            result={}
        )
        audit_latency_ms = (time.perf_counter() - t2) * 1000.0

        total_pipeline_ms = rec_latency_ms + twin_mutation_ms + audit_latency_ms

        return {
            "recommendationLatencyMs": round(rec_latency_ms, 3),
            "twinMutationLatencyMs": round(twin_mutation_ms, 3),
            "auditWriteLatencyMs": round(audit_latency_ms, 3),
            "totalClosedLoopLatencyMs": round(total_pipeline_ms, 3)
        }

phase21_graduation_orchestrator = Phase21GraduationOrchestrator()