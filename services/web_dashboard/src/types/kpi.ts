import { NavigationRouteId } from "./dashboard";

export interface DeviceStatusBreakdown {
  total: number;
  normal: number;
  monitored: number;
  suspicious: number;
  atRisk: number;
  compromised: number;
  isolated: number;
}

export interface ThreatSeverityBreakdown {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface NetworkRiskSummary {
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  score: number;
  scoreFormatted: string;
  trend: "INCREASING" | "DECREASING" | "STABLE" | "VOLATILE" | "UNKNOWN";
  highestRiskDevice: string;
}

export interface AttackScenarioSummary {
  activeCount: number;
  totalConfigured: number;
  runningScenarios: string[];
}

export interface CriticalAssetItem {
  deviceId: string;
  hostname: string;
  zone: string;
  criticality: "HIGH" | "CRITICAL";
  riskScore: number;
  status: string;
}

export interface ExecutiveKpiPayload {
  devices: DeviceStatusBreakdown;
  threats: ThreatSeverityBreakdown;
  risk: NetworkRiskSummary;
  attacks: AttackScenarioSummary;
  criticalAssets: CriticalAssetItem[];
  openAlertsCount: number;
  activePredictionsCount: number;
  timestamp: string;
}