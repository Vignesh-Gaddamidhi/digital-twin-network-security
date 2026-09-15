from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class SimulationExecutionState(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    COMPLETED = "COMPLETED"

class SimulationStageEnum(str, Enum):
    NORMAL = "NORMAL"
    EARLY_INDICATORS = "EARLY_INDICATORS"
    ESCALATION = "ESCALATION"
    IMPACT = "IMPACT"
    RECOVERY = "RECOVERY"

class ScenarioIdentifierEnum(str, Enum):
    # Micro-traffic patterns
    NORMAL = "NORMAL"
    TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    CONNECTION_ANOMALY = "CONNECTION_ANOMALY"
    PORT_ANOMALY = "PORT_ANOMALY"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    REPEATED_CONNECTION = "REPEATED_CONNECTION"

    # Attack Scenarios
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE_LIKE = "BRUTE_FORCE_LIKE"
    DOS_LIKE = "DOS_LIKE"
    DNS_ANOMALY = "DNS_ANOMALY"
    BEACONING = "BEACONING"
    LATERAL_MOVEMENT_LIKE = "LATERAL_MOVEMENT_LIKE"
    EXFILTRATION_LIKE = "EXFILTRATION_LIKE"

class SimulationConfiguration(BaseModel):
    scenario: ScenarioIdentifierEnum = ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE
    durationSeconds: int = 120
    seed: int = 42
    speedMultiplier: float = 1.0  # 1.0x, 2.0x, 5.0x
    tickIntervalMs: int = 500
    predictionHorizonSec: int = 60

class SimulationReproducibilityMeta(BaseModel):
    simulationId: str = Field(default_factory=lambda: f"SIM-{uuid.uuid4().hex[:6].upper()}")
    scenarioId: str = "LATERAL_MOVEMENT_LIKE"
    seed: int = 42
    runId: str = Field(default_factory=lambda: f"RUN-{uuid.uuid4().hex[:8].upper()}")
    startedAt: Optional[str] = None
    completedAt: Optional[str] = None

class SimulationLiveStateView(BaseModel):
    executionState: SimulationExecutionState = SimulationExecutionState.IDLE
    currentStage: SimulationStageEnum = SimulationStageEnum.NORMAL
    elapsedSeconds: int = 0
    totalSeconds: int = 120
    timeDisplay: str = "00:00 / 02:00"
    progressPercent: float = 0.0
    activeScenario: ScenarioIdentifierEnum = ScenarioIdentifierEnum.LATERAL_MOVEMENT_LIKE
    reproducibility: SimulationReproducibilityMeta = Field(default_factory=SimulationReproducibilityMeta)
    config: SimulationConfiguration = Field(default_factory=SimulationConfiguration)

    # Cascaded Telemetry Indicators
    currentPacketsPerSec: float = 120.0
    activeEventsCount: int = 0
    predictedThreatProb: float = 0.08
    networkRiskScore: float = 12.0
    activeAttackPathsCount: int = 0
    lastStageTransition: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def render_cli_panel(self) -> str:
        stages = ["NORMAL", "EARLY_INDICATORS", "ESCALATION", "IMPACT", "RECOVERY"]
        stage_viz = []
        for s in stages:
            if s == self.currentStage.value:
                stage_viz.append(f"[{s}*]")
            else:
                stage_viz.append(s)
        stage_flow = " ──> ".join(stage_viz)

        lines = [
            "╔══════════════════════════════════════════════════════════════════════════════╗",
            "║                      SIMULATION CONTROL CENTER                               ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ State: {self.executionState.value:<10} │ Scenario: {self.activeScenario.value:<22} Time: {self.timeDisplay:<12} ║",
            f"║ Progress: {self.progressPercent:5.1f}% │ Speed: {self.config.speedMultiplier:3.1f}x │ Tick: {self.config.tickIntervalMs}ms │ Seed: {self.reproducibility.seed:<8} ║",
            f"║ Run ID: {self.reproducibility.runId:<14} │ Simulation ID: {self.reproducibility.simulationId:<25} ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ STAGE TIMELINE: {stage_flow:<60} ║",
            "╠══════════════════════════════════════════════════════════════════════════════╣",
            f"║ CASCADED DASHBOARD STATUS:                                                   ║",
            f"║ * Traffic: {self.currentPacketsPerSec:6.1f} pkts/s │ Events: {self.activeEventsCount:02d} │ ML Threat: {self.predictedThreatProb*100:4.1f}% │ Risk: {self.networkRiskScore:4.1f}/100 ║",
            f"║ * Active Traversal Paths Discovered: {self.activeAttackPathsCount:02d}                                        ║",
            "╚══════════════════════════════════════════════════════════════════════════════╝"
        ]
        return "\n".join(lines)