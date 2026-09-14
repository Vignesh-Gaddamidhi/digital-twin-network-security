import React from "react";
import { CriticalAssetItem } from "../../types/kpi";
import { NavigationRouteId } from "../../types/dashboard";

interface CriticalAssetsPanelProps {
  assets: CriticalAssetItem[];
  onNavigate: (route: NavigationRouteId) => void;
}

export const CriticalAssetsPanel: React.FC<CriticalAssetsPanelProps> = ({ assets, onNavigate }) => {
  return (
    <div className="p-4 rounded-lg border border-border bg-card mt-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-destructive animate-pulse" />
          <h3 className="text-xs uppercase font-mono tracking-wider font-semibold text-foreground">
            Critical Assets at Risk
          </h3>
        </div>
        <button
          onClick={() => onNavigate("topology")}
          className="text-xs text-primary hover:underline font-mono"
        >
          View Topology →
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {assets.map((a) => (
          <div
            key={a.deviceId}
            onClick={() => onNavigate("topology")}
            className="p-3 rounded border border-border bg-muted/20 hover:border-primary/40 cursor-pointer flex flex-col justify-between"
          >
            <div className="flex items-center justify-between">
              <strong className="text-xs font-mono text-foreground">{a.deviceId}</strong>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-destructive/15 text-destructive border border-destructive/25">
                {a.criticality}
              </span>
            </div>
            <div className="text-[11px] text-muted-foreground mt-1 truncate">{a.hostname}</div>
            <div className="mt-2 flex items-center justify-between text-[11px] font-mono">
              <span className="text-muted-foreground">Zone: {a.zone}</span>
              <span className="text-foreground">Risk: {a.riskScore.toFixed(1)}/100</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};