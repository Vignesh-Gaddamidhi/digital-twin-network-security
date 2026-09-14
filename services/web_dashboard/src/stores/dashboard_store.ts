import {
  NavigationRouteId,
  NavigationItem,
  ComponentUiState,
  SystemHeaderContext
} from "../types/dashboard";

export const MAIN_NAVIGATION_ITEMS: NavigationItem[] = [
  { id: "overview", label: "Dashboard", iconName: "LayoutDashboard" },
  { id: "topology", label: "Network Topology", iconName: "Network" },
  { id: "traffic", label: "Traffic", iconName: "Activity" },
  { id: "threats", label: "Threat Detection", iconName: "ShieldAlert", badgeCount: 3, badgeVariant: "warning" },
  { id: "predictions", label: "Predictions", iconName: "BrainCircuit" },
  { id: "risk", label: "Risk Scoring", iconName: "Gauge", badgeCount: 1, badgeVariant: "destructive" },
  { id: "attack-paths", label: "Attack Paths", iconName: "GitBranch" },
  { id: "alerts", label: "Security Alerts", iconName: "Bell", badgeCount: 4, badgeVariant: "destructive" },
  { id: "simulation", label: "Simulation Control", iconName: "PlayCircle" },
  { id: "devices", label: "Devices", iconName: "Server" },
  { id: "settings", label: "Settings", iconName: "Settings" }
];

export const INITIAL_SYSTEM_CONTEXT: SystemHeaderContext = {
  systemTitle: "NETWORK SECURITY DIGITAL TWIN",
  systemStatus: "ONLINE",
  simulationState: "RUNNING",
  environmentName: "LAB / SIMULATION",
  activeScenario: "LATERAL_MOVEMENT_LIKE",
  timestamps: {
    eventTime: new Date().toISOString(),
    receivedTime: new Date().toISOString(),
    processedTime: new Date().toISOString(),
    predictionTime: new Date().toISOString(),
    lastUpdated: new Date().toLocaleTimeString()
  }
};