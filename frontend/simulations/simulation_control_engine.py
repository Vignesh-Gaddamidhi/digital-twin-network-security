from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import math
import uuid

from frontend.dashboard.dashboard_engine import dashboard_engine
from frontend.dashboard.device_inspection_engine import device_inspection_engine
from frontend.traffic.traffic_monitoring_engine import traffic_monitoring_engine
from frontend.traffic.traffic_models import TrafficPointDetail
from frontend.threats.threat_timeline_engine import threat_timeline_engine
from frontend.threats.threat_models import ThreatTimelineItem, DetectionSourceEnum
from frontend.risk.risk_dashboard_engine import risk_dashboard_engine
from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.nodes.entry_point_engine import entry_point_engine
from frontend.simulations.simulation_models import (
    SimulationExecutionState, SimulationStageEnum, ScenarioIdentifierEnum,
    SimulationConfiguration, SimulationReproducibilityMeta, SimulationLiveStateView
)

class SimulationControlEngine:
    """Controls scenario lifecycle, multi-stage timeline transitions, and downstream dashboard cascading."""

    def __init__(self):
        self.config = SimulationConfiguration()
        self.reproducibility = SimulationReproducibilityMeta()
        self.live_state = SimulationLiveStateView(
            config=self.config,
            reproducibility=self.reproducibility
        )

    def select_scenario(
        self,
        scenario: ScenarioIdentifierEnum,
        duration_seconds: int = 120,
        seed: int = 42,
        speed: float = 1.0
    ) -> SimulationLiveStateView:
        self.config = SimulationConfiguration(
            scenario=scenario,
            durationSeconds=duration_seconds,
            seed=seed,
            speedMultiplier=speed
        )
        self.reproducibility = SimulationReproducibilityMeta(
            scenarioId=scenario.value,
            seed=seed
        )
        self.live_state = SimulationLiveStateView(
            executionState=SimulationExecutionState.IDLE,
            currentStage=SimulationStageEnum.NORMAL,
            elapsedSeconds=0,
            totalSeconds=duration_seconds,
            timeDisplay=f"00:00 / {self._fmt_time(duration_seconds)}",
            progressPercent=0.0,
            activeScenario=scenario,
            reproducibility=self.reproducibility,
            config=self.config
        )
        return self.live_state

    def start(self) -> SimulationLiveStateView:
        self.live_state.executionState = SimulationExecutionState.RUNNING
        self.reproducibility.startedAt = datetime.now(timezone.utc).isoformat()
        self._cascade_dashboard_update()
        return self.live_state

    def pause(self) -> SimulationLiveStateView:
        if self.live_state.executionState == SimulationExecutionState.RUNNING:
            self.live_state.executionState = SimulationExecutionState.PAUSED
        return self.live_state

    def resume(self) -> SimulationLiveStateView:
        if self.live_state.executionState == SimulationExecutionState.PAUSED:
            self.live_state.executionState = SimulationExecutionState.RUNNING
        return self.live_state

    def stop(self) -> SimulationLiveStateView:
        self.live_state.executionState = SimulationExecutionState.STOPPED
        self.reproducibility.completedAt = datetime.now(timezone.utc).isoformat()
        return self.live_state

    def reset(self) -> SimulationLiveStateView:
        return self.select_scenario(
            scenario=self.config.scenario,
            duration_seconds=self.config.durationSeconds,
            seed=self.config.seed,
            speed=self.config.speedMultiplier
        )

    def advance_ticks(self, seconds: int) -> SimulationLiveStateView:
        if self.live_state.executionState != SimulationExecutionState.RUNNING:
            return self.live_state

        eff_seconds = int(seconds * self.config.speedMultiplier)
        self.live_state.elapsedSeconds = min(self.config.durationSeconds, self.live_state.elapsedSeconds + eff_seconds)
        self.live_state.progressPercent = round((self.live_state.elapsedSeconds / self.config.durationSeconds) * 100.0, 1)
        self.live_state.timeDisplay = f"{self._fmt_time(self.live_state.elapsedSeconds)} / {self._fmt_time(self.config.durationSeconds)}"

        # Determine Stage based on progress percentage
        p = self.live_state.progressPercent
        old_stage = self.live_state.currentStage

        if p < 20.0:
            self.live_state.currentStage = SimulationStageEnum.NORMAL
        elif p < 45.0:
            self.live_state.currentStage = SimulationStageEnum.EARLY_INDICATORS
        elif p < 70.0:
            self.live_state.currentStage = SimulationStageEnum.ESCALATION
        elif p < 90.0:
            self.live_state.currentStage = SimulationStageEnum.IMPACT
        else:
            self.live_state.currentStage = SimulationStageEnum.RECOVERY

        if p >= 100.0:
            self.live_state.executionState = SimulationExecutionState.COMPLETED
            self.reproducibility.completedAt = datetime.now(timezone.utc).isoformat()

        if self.live_state.currentStage != old_stage:
            self.live_state.lastStageTransition = datetime.now(timezone.utc).isoformat()

        self._cascade_dashboard_update()
        return self.live_state

    def _cascade_dashboard_update(self):
        stage = self.live_state.currentStage
        scenario = self.config.scenario

        # Calculate cascaded state parameters based on timeline stage
        if stage == SimulationStageEnum.NORMAL:
            pkt_rate = 120.0
            events_c = 1
            threat_p = 0.08
            risk_s = 12.0
            paths_c = 0
            entry_point_engine.set_simulation_compromise("CLIENT-01", "NORMAL")
        elif stage == SimulationStageEnum.EARLY_INDICATORS:
            pkt_rate = 340.0
            events_c = 3
            threat_p = 0.42
            risk_s = 38.4
            paths_c = 1
            entry_point_engine.set_simulation_compromise("CLIENT-01", "SUSPICIOUS", scenario_id=scenario.value)
        elif stage == SimulationStageEnum.ESCALATION:
            pkt_rate = 890.0
            events_c = 6
            threat_p = 0.78
            risk_s = 69.6
            paths_c = 2
            entry_point_engine.set_simulation_compromise("CLIENT-01", "COMPROMISED", scenario_id=scenario.value)
        elif stage == SimulationStageEnum.IMPACT:
            pkt_rate = 1850.0
            events_c = 10
            threat_p = 0.96
            risk_s = 89.6
            paths_c = 3
            entry_point_engine.set_simulation_compromise("WEB-01", "COMPROMISED", scenario_id=scenario.value)
        else:  # RECOVERY
            pkt_rate = 210.0
            events_c = 2
            threat_p = 0.25
            risk_s = 24.0
            paths_c = 0
            entry_point_engine.set_simulation_compromise("CLIENT-01", "NORMAL")

        self.live_state.currentPacketsPerSec = pkt_rate
        self.live_state.activeEventsCount = events_c
        self.live_state.predictedThreatProb = threat_p
        self.live_state.networkRiskScore = risk_s
        self.live_state.activeAttackPathsCount = paths_c

        # Push to downstream engines
        dashboard_engine.update_telemetry_feed(
            devices_count=12,
            active_threats=events_c,
            network_risk_score=risk_s,
            network_risk_level="CRITICAL" if risk_s > 75.0 else ("HIGH" if risk_s > 50.0 else "MEDIUM"),
            attack_paths_count=paths_c,
            packets_per_sec=pkt_rate
        )

    def _fmt_time(self, seconds: int) -> str:
        m = seconds // 60
        s = seconds % 60
        return f"{m:02d}:{s:02d}"

simulation_control_engine = SimulationControlEngine()