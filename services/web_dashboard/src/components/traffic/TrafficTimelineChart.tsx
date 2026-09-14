import React from "react";
import { TrafficTimeSeriesPoint, TrafficAnomalyNotice } from "../../types/traffic";

interface TrafficTimelineChartProps {
  timeline: TrafficTimeSeriesPoint[];
  anomaly: TrafficAnomalyNotice;
}

export const TrafficTimelineChart: React.FC<TrafficTimelineChartProps> = ({ timeline, anomaly }) => {
  const maxRate = Math.max(...timeline.map((t) => t.packetRate), 100);

  return (
    <div className="p-4 rounded-lg border border-border bg-card flex flex-col justify-between h-full">
      <div>
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs uppercase font-mono font-semibold text-foreground tracking-wider">
            Throughput Velocity Timeline (Packets/Sec)
          </h4>
          {anomaly.detected && (
            <span className="flex items-center gap-1.5 text-[10px] font-mono px-2 py-0.5 rounded bg-destructive/15 text-destructive border border-destructive/30 animate-pulse">
              ⚠ {anomaly.anomalyType || "TRAFFIC ANOMALY"}
            </span>
          )}
        </div>

        {/* ASCII/SVG Simplified Stepped Bar Curve */}
        <div className="h-44 w-full flex items-end gap-1 pt-6 pb-2 border-b border-border/60">
          {timeline.map((pt, i) => {
            const pct = (pt.packetRate / maxRate) * 100;
            return (
              <div key={i} className="flex-1 flex flex-col items-center h-full justify-end group relative">
                <div
                  className={`w-full rounded-t transition-all ${
                    pt.isAnomaly ? "bg-destructive" : "bg-primary/70 group-hover:bg-primary"
                  }`}
                  style={{ height: `${Math.max(6, pct)}%` }}
                />
                {/* Tooltip on hover */}
                <div className="absolute -top-7 hidden group-hover:block z-10 px-1.5 py-0.5 rounded bg-popover text-popover-foreground text-[10px] font-mono whitespace-nowrap shadow border border-border">
                  {pt.packetRate} pkts/s
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex justify-between text-[10px] font-mono text-muted-foreground mt-1.5">
          <span>{timeline[0]?.timeLabel || "T-5m"}</span>
          <span>Live Ingestion</span>
          <span>{timeline[timeline.length - 1]?.timeLabel || "Now"}</span>
        </div>
      </div>

      {anomaly.detected && (
        <div className="mt-3 p-2.5 rounded border border-destructive/30 bg-destructive/10 text-destructive text-xs font-mono flex items-center justify-between">
          <span>{anomaly.description}</span>
          {anomaly.correlatedEventId && (
            <strong className="underline cursor-pointer">{anomaly.correlatedEventId}</strong>
          )}
        </div>
      )}
    </div>
  );
};