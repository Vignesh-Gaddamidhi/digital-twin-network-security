export type TrafficTimeRange = "1m" | "5m" | "15m" | "1h" | "SIMULATION";

export type SupportedProtocol = "ALL" | "TCP" | "UDP" | "ICMP" | "HTTP" | "HTTPS" | "DNS" | "SSH";

export interface ProtocolShare {
  protocol: string;
  percentage: number;
  packetCount: number;
  byteCount: number;
}

export interface TrafficTimeSeriesPoint {
  timestamp: string;
  timeLabel: string;
  packetRate: number;     // pkts/s
  byteRate: number;       // bytes/s
  isAnomaly: boolean;
}

export interface ConnectionMetrics {
  active: number;
  successful: number;
  failed: number;
  failureRate: number;    // e.g. 9.5%
}

export interface TrafficAnomalyNotice {
  detected: boolean;
  anomalyType?: string;
  severity?: "WARNING" | "CRITICAL";
  affectedDevice?: string;
  correlatedEventId?: string;
  description?: string;
}

export interface LiveTrafficPayload {
  packetRate: number;
  packetRateFormatted: string;
  byteRate: number;
  byteRateFormatted: string;
  totalVolumeBytes: number;
  totalVolumeFormatted: string;
  connections: ConnectionMetrics;
  protocols: ProtocolShare[];
  timeline: TrafficTimeSeriesPoint[];
  anomaly: TrafficAnomalyNotice;
  filteredDevice: string;
  selectedTimeRange: TrafficTimeRange;
  timestamp: string;
}