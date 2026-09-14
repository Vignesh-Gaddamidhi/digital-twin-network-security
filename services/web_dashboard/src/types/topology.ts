import { NetworkZoneEnum, ReachabilityStateEnum } from "../../../digital_twin/attack_path/graph/security_zone_models";
import { RiskLevelTier } from "../../../digital_twin/risk/factors/factor_types";

export interface TopologyNodePoint {
  id: string;
  deviceId: string;
  hostname: string;
  ip: string;
  mac?: string;
  zone: string;
  deviceType: string;
  assetCriticality: string;
  securityState: "NORMAL" | "MONITORED" | "SUSPICIOUS" | "AT_RISK" | "COMPROMISED" | "ISOLATED" | "UNKNOWN";
  riskScore: number;
  riskLevel: RiskLevelTier;
  openPorts: number[];
  services: string[];
  vulnerabilities: string[];
  x: number;
  y: number;
  isHighlighted?: boolean;
}

export interface TopologyEdgeLink {
  id: string;
  source: string;
  target: string;
  protocol: string;
  destinationPort: number;
  service: string;
  reachability: "REACHABLE" | "RESTRICTED" | "BLOCKED" | "UNKNOWN";
  securityControl?: string;
  isHighlighted?: boolean;
  status: string;
}

export interface NetworkZoneBoundary {
  zone: string;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
  color: string;
}

export interface LiveTopologyPayload {
  zones: NetworkZoneBoundary[];
  nodes: TopologyNodePoint[];
  edges: TopologyEdgeLink[];
  totalNodes: number;
  totalEdges: number;
  timestamp: string;
}