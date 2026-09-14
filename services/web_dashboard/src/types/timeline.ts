export type TimelineCategory =
  | "ALL"
  | "THREATS"
  | "ALERTS"
  | "PREDICTIONS"
  | "RISK"
  | "ATTACK_PATHS"
  | "SIMULATION"
  | "IDS";

export type EventSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ThreatTimelineEvent {
  eventId: string;
  timestamp: string;
  timeLabel: string;
  category: TimelineCategory;
  eventType: string;
  severity: EventSeverity;
  sourceDevice: string;
  destinationDevice?: string;
  protocol: string;
  port?: number;
  detectionSource: string; // e.g. "SURICATA", "ML_RANDOM_FOREST", "RISK_ENGINE", "PATH_ENGINE"
  description: string;
  
  // Drill-down linkage
  confidence?: number;
  riskScore?: number;
  predictionId?: string;
  pathId?: string;
  topFeatures?: string[];
  evidenceText?: string;
}

export interface TimelineFilterCriteria {
  category: TimelineCategory;
  severity: string; // "ALL" | EventSeverity
  deviceId: string; // "ALL" or specific host
  searchTerm?: string;
}

export interface ThreatTimelinePayload {
  events: ThreatTimelineEvent[];
  totalEvents: number;
  filteredCount: number;
  categoryCounts: Record<string, number>;
  timestamp: string;
}