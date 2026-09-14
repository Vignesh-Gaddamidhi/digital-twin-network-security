import React from "react";
import { ProtocolShare } from "../../types/traffic";

interface ProtocolDistributionChartProps {
  protocols: ProtocolShare[];
}

export const ProtocolDistributionChart: React.FC<ProtocolDistributionChartProps> = ({ protocols }) => {
  return (
    <div className="p-4 rounded-lg border border-border bg-card flex flex-col justify-between h-full">
      <div>
        <h4 className="text-xs uppercase font-mono font-semibold text-foreground tracking-wider mb-3">
          Protocol Distribution
        </h4>
        <div className="space-y-2.5">
          {protocols.map((p) => (
            <div key={p.protocol} className="text-xs font-mono">
              <div className="flex justify-between text-muted-foreground mb-1">
                <span className="font-semibold text-foreground">{p.protocol}</span>
                <span>{p.percentage.toFixed(1)}% ({p.packetCount.toLocaleString()} pkts)</span>
              </div>
              <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full bg-primary rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, p.percentage)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-4 pt-3 border-t border-border text-[11px] text-muted-foreground font-mono flex justify-between">
        <span>Deep Packet Ingestion: Active</span>
        <span>7 Protocols Bound</span>
      </div>
    </div>
  );
};