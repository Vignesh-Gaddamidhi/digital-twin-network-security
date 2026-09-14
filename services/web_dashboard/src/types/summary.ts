import { ExecutiveKpiPayload } from "./kpi";
import { LiveTopologyPayload } from "./topology";
import { LiveTrafficPayload } from "./traffic";
import { ThreatTimelinePayload } from "./timeline";
import { PredictionXaiPayload } from "./prediction";
import { SystemHeaderContext } from "./dashboard";

export interface SimulationControlState {
  status: "RUNNING" | "PAUSED" | "STOPPED" | "RESET";
  activeScenario: string;
  speedMultiplier: number; // 1x, 2x, 5x
  elapsedSimulationTime: string; // e.g. "00:12:31"
  tickCount: number;
}

export interface MasterDashboardSummaryPayload {
  header: SystemHeaderContext;
  simulationControl: SimulationControlState;
  kpis: ExecutiveKpiPayload;
  topology: LiveTopologyPayload;
  traffic: LiveTrafficPayload;
  timeline: ThreatTimelinePayload;
  prediction: PredictionXaiPayload;
  topAttackPath: {
    pathId: string;
    route: string[];
    riskScore: number;
    riskLevel: string;
    criticalTarget: boolean;
    status: string;
    explanation: string;
  };
  stateConsistencyHash: string;
  timestamp: string;
}