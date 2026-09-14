import React from "react";
import { ConnectionMetrics } from "../../types/traffic";

interface TrafficMetricCardsProps {
  packetRateFormatted: string;
  byteRateFormatted: string;
  totalVolumeFormatted: string;
  connections: ConnectionMetrics;
}

export const TrafficMetricCards: React.FC<TrafficMetricCardsProps> = ({
  packetRateFormatted,
  byteRateFormatted,
  totalVolumeFormatted,
  connections
}) => {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <div className="p-3.5 rounded-lg border border-border bg-card">
        <span className="text-[11px] uppercase font-mono text-muted-foreground">Packet Rate</span>
        <div className="mt-1 text-xl font-bold font-mono text-foreground">{packetRateFormatted}</div>
        <span className="text-[10px] text-muted-foreground">Real-time throughput</span>
      </div>

      <div className="p-3.5 rounded-lg border border-border bg-card">
        <span className="text-[11px] uppercase font-mono text-muted-foreground">Byte Velocity</span>
        <div className="mt-1 text-xl font-bold font-mono text-foreground">{byteRateFormatted}</div>
        <span className="text-[10px] text-muted-foreground">Total Vol: {totalVolumeFormatted}</span>
      </div>

      <div className="p-3.5 rounded-lg border border-border bg-card">
        <span className="text-[11px] uppercase font-mono text-muted-foreground">Active Connections</span>
        <div className="mt-1 text-xl font-bold font-mono text-foreground">{connections.active}</div>
        <span className="text-[10px] text-emerald-500 font-mono">{connections.successful} successful handshakes</span>
      </div>

      <div className="p-3.5 rounded-lg border border-border bg-card">
        <div className="flex justify-between items-center">
          <span className="text-[11px] uppercase font-mono text-muted-foreground">Failed Connections</span>
          <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
            connections.failureRate > 8.0
              ? "bg-destructive/15 text-destructive border border-destructive/25"
              : "bg-muted text-muted-foreground"
          }`}>
            {connections.failureRate.toFixed(1)}%
          </span>
        </div>
        <div className="mt-1 text-xl font-bold font-mono text-destructive">{connections.failed}</div>
        <span className="text-[10px] text-muted-foreground">Connection reset / drops</span>
      </div>
    </div>
  );
};