export type ComponentUiState = "LOADING" | "SUCCESS" | "EMPTY" | "ERROR" | "STALE" | "OFFLINE";

export type SimulationRunState = "RUNNING" | "PAUSED" | "STOPPED" | "REPLAYING";

export type SystemStatusState = "ONLINE" | "DEGRADED" | "OFFLINE";

export type NavigationRouteId =
  | "overview"
  | "topology"
  | "traffic"
  | "threats"
  | "predictions"
  | "risk"
  | "attack-paths"
  | "alerts"
  | "simulation"
  | "devices"
  | "settings";

export interface NavigationItem {
  id: NavigationRouteId;
  label: string;
  iconName: string;
  badgeCount?: number;
  badgeVariant?: "default" | "destructive" | "warning";
}

export interface DashboardTimestampLedger {
  eventTime: string;      // When telemetry originally occurred
  receivedTime: string;   // When twin engine ingested the frame
  processedTime: string;  // When feature extraction & inference finished
  predictionTime: string; // When ML / XAI / Risk score was calculated
  lastUpdated: string;    // Current dashboard sync timestamp
}

export interface SystemHeaderContext {
  systemTitle: string;
  systemStatus: SystemStatusState;
  simulationState: SimulationRunState;
  environmentName: "LAB / SIMULATION";
  activeScenario: string;
  timestamps: DashboardTimestampLedger;
}