from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import time

from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine
from frontend.simulations.simulation_models import ScenarioIdentifierEnum
from frontend.realtime.realtime_models import (
    RealtimeEventType, RealtimeConnectionState, DataFreshnessState, BackendHealthState,
    RealtimeEventEnvelope
)
from frontend.realtime.realtime_event_manager import realtime_event_manager
from frontend.realtime.websocket_gateway import websocket_connection_manager
from frontend.realtime.simulation_realtime_pipeline import simulation_realtime_pipeline
from frontend.realtime.live_telemetry_engine import live_telemetry_engine, ConnectionLifecycleState
from frontend.realtime.live_security_engine import live_security_engine, EarlyWarningStateEnum
from frontend.realtime.realtime_store_engine import realtime_store_engine

class Phase20GraduationOrchestrator:
    """Master orchestrator executing full real-time digital twin integration, stress tests, and latency profiling."""

    async def run_complete_live_lifecycle(self) -> Dict[str, Any]:
        """Runs the comprehensive E2E live scenario from baseline through attack, prediction, isolation, and restoration."""
        # 1. Baseline initialization
        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        device_3d_renderer_engine.sync_devices_from_twin()
        link_3d_renderer_engine.sync_links_from_twin()

        snap = realtime_event_manager.generate_full_twin_snapshot()
        realtime_store_engine.apply_snapshot(snap)

        # 2. Start Simulation & Stream Normal Traffic
        await simulation_realtime_pipeline.start_simulation(ScenarioIdentifierEnum.NORMAL)
        env_traffic = await live_telemetry_engine.update_traffic_flow(
            source_device_id="CLIENT-01", destination_device_id="WEB-01", packet_rate=120.0
        )
        realtime_store_engine.apply_event_envelope(env_traffic)

        # 3. CPU/Memory Live Updates
        env_cpu = await live_telemetry_engine.update_device_cpu("WEB-01", 76.5)
        realtime_store_engine.apply_event_envelope(env_cpu)

        # 4. Connection State Machine: NEW -> ESTABLISHED
        env_conn = await live_telemetry_engine.update_connection_lifecycle(
            "CONN-ACTIVE-01", "CLIENT-01", "WEB-01", ConnectionLifecycleState.ESTABLISHED
        )
        realtime_store_engine.apply_event_envelope(env_conn)

        # 5. Threat Detection & Timeline Injection
        env_threat = await live_security_engine.emit_threat_update(
            source_device_id="ATTACKER-EXT", target_device_id="WEB-01",
            event_type="SQLI_LATERAL_PROBE", severity=RiskLevelTier.HIGH
        )
        realtime_store_engine.apply_event_envelope(env_threat)

        # 6. ML Prediction & Early Warning
        env_pred = await live_security_engine.emit_prediction_update(
            device_id="WEB-01", current_prob=0.48, future_prob=0.91,
            predicted_category="LATERAL_MOVEMENT", risk_score=82.4
        )
        realtime_store_engine.apply_event_envelope(env_pred)

        env_ew = await live_security_engine.emit_early_warning_update(
            device_id="WEB-01", lead_time_seconds=35, future_prob=0.91,
            warning_state=EarlyWarningStateEnum.HIGH_CONFIDENCE_WARNING
        )
        realtime_store_engine.apply_event_envelope(env_ew)

        # 7. Dynamic Risk Re-calculation & Attack Path Illumination
        env_risk = await live_security_engine.update_device_risk(
            device_id="WEB-01", threat_prob=0.91, criticality=1.0, vulnerability_factor=0.8, impact=1.0
        )
        realtime_store_engine.apply_event_envelope(env_risk)

        env_path = await live_security_engine.trigger_live_attack_path_highlight()
        realtime_store_engine.apply_event_envelope(env_path)

        # 8. Alert Dispatch
        env_alert = await live_security_engine.emit_alert_update(
            source_device="WEB-01", destination_device="DB-01",
            event_type="UNAUTHORIZED_LATERAL_ACCESS", severity=RiskLevelTier.CRITICAL, risk_score=82.4
        )
        realtime_store_engine.apply_event_envelope(env_alert)

        # 9. Simulated Response: Quarantine CLIENT-01
        twin_graph_synchronizer.isolate_device("CLIENT-01")
        if "CLIENT-01" in attack_path_graph.nodes:
            attack_path_graph.nodes["CLIENT-01"].securityState = "ISOLATED"
        device_3d_renderer_engine.sync_devices_from_twin()

        env_iso = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.DEVICE_STATE_UPDATE,
            payload={"deviceId": "CLIENT-01", "newState": "ISOLATED", "quarantineEnforced": True},
            device_id="CLIENT-01"
        )
        realtime_store_engine.apply_event_envelope(env_iso)

        isolated_state_2d = attack_path_graph.nodes["CLIENT-01"].securityState
        isolated_state_store = realtime_store_engine.devices["CLIENT-01"].securityState
        isolated_cage_3d = device_3d_renderer_engine.device_mesh_registry["CLIENT-01"].selectionState

        # 10. Recovery Restoration
        await simulation_realtime_pipeline.reset_simulation()
        clean_snap = realtime_event_manager.generate_full_twin_snapshot()
        realtime_store_engine.apply_snapshot(clean_snap)

        return {
            "trafficPacketRate": env_traffic.payload["packetsPerSecond"],
            "webCpuPct": env_cpu.payload["cpuUtilizationPct"],
            "connectionState": env_conn.payload["status"],
            "threatId": env_threat.payload["threatId"],
            "predictedCategory": env_pred.payload["predictedCategory"],
            "earlyWarningLeadTime": env_ew.payload["leadTimeSeconds"],
            "updatedRiskScore": env_risk.payload["compositeRiskScore"],
            "attackPathChain": env_path.payload["nodeSequence"],
            "isolatedState2D": isolated_state_2d,
            "isolatedStateStore": isolated_state_store,
            "restoredState": realtime_store_engine.devices["WEB-01"].securityState
        }

    def profile_realtime_latency_and_throughput(self) -> Dict[str, Any]:
        """Profiles real-time message throughput, end-to-end propagation latencies, and device scaling."""
        results = {}

        # 1. Device Scaling Timing (10, 25, 50, 100 devices)
        for count in [10, 25, 50, 100]:
            t0 = time.perf_counter()
            for i in range(count):
                did = f"DEV-{i:03d}"
                _ = realtime_event_manager.build_envelope(
                    event_type=RealtimeEventType.CPU_UPDATE,
                    payload={"deviceId": did, "cpuUtilizationPct": 25.0},
                    device_id=did
                )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            results[f"envelopePackaging_{count}_devices_ms"] = round(elapsed_ms, 3)

        # 2. Event Ingestion & Store Processing Throughput (100, 500, 1000 events/sec simulation)
        for volume in [100, 500, 1000]:
            t0 = time.perf_counter()
            for i in range(volume):
                env = realtime_event_manager.build_envelope(
                    event_type=RealtimeEventType.TRAFFIC_UPDATE,
                    payload={"linkId": "L-TEST", "packetsPerSecond": float(i)}
                )
                realtime_store_engine.apply_event_envelope(env)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            results[f"storeProcessing_{volume}_events_ms"] = round(elapsed_ms, 3)
            results[f"throughput_{volume}_events_per_sec"] = round(volume / max(0.001, elapsed_ms / 1000.0), 1)

        # 3. Latency Timestamp Differential Tracking (Event -> Processed)
        t_start = datetime.now(timezone.utc)
        env_sample = realtime_event_manager.build_envelope(
            event_type=RealtimeEventType.CPU_UPDATE,
            payload={"deviceId": "WEB-01", "cpuUtilizationPct": 50.0}
        )
        realtime_store_engine.apply_event_envelope(env_sample)
        t_end = datetime.now(timezone.utc)

        total_latency_ms = (t_end - t_start).total_seconds() * 1000.0
        results["e2eEventProcessingLatencyMs"] = round(total_latency_ms, 3)

        return results

phase20_graduation_orchestrator = Phase20GraduationOrchestrator()