export type DeviceType = "FIREWALL" | "ROUTER" | "SWITCH" | "WEB_SERVER" | "DB_SERVER" | "WORKSTATION";
export type NodeHealth = "HEALTHY" | "SUSPICIOUS" | "COMPROMISED" | "ISOLATED";

export interface NetworkInterface {
  id: string;
  ipAddress: string;
  macAddress: string;
  subnetMask: string;
}

export interface NetworkNode {
  id: string;
  label: string;
  type: DeviceType;
  interfaces: NetworkInterface[];
  openPorts: number[];
  services: string[];
  vulnerabilities: string[];
  health: NodeHealth;
  compromiseProbability: number;
  criticality: number; // Scale 1 - 10
}

export interface NetworkLink {
  id: string;
  source: string;
  target: string;
  bandwidthMbps: number;
  latencyMs: number;
  isEncrypted: boolean;
  activeFlowCount: number;
}

export interface DigitalTwinGraph {
  nodes: NetworkNode[];
  links: NetworkLink[];
  timestamp: string;
}

export interface AttackPredictionAlert {
  alertId: string;
  sourceIp: string;
  targetNodeId: string;
  attackCategory: string;
  confidenceScore: number;
  killChainStage: string;
  predictedNextTarget: string;
  contributingFeatures: { feature: string; impact: number }[];
  timestamp: string;
}