import React from "react";
import { TopologyNodePoint } from "../../types/topology";

interface DeviceDetailFlyoutProps {
  device: TopologyNodePoint | null;
  onClose: () => void;
  onIsolate?: (deviceId: string) => void;
}

export const DeviceDetailFlyout: React.FC<DeviceDetailFlyoutProps> = ({ device, onClose, onIsolate }) => {
  if (!device) return null;

  return (
    <aside className="fixed top-16 right-0 w-80 h-[calc(100vh-4rem)] border-l border-border bg-card/95 backdrop-blur-md shadow-2xl z-40 p-4 flex flex-col justify-between overflow-y-auto">
      <div>
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div>
            <h3 className="text-sm font-bold font-mono text-foreground">{device.deviceId}</h3>
            <span className="text-xs text-muted-foreground">{device.hostname}</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
          >
            ✕
          </button>
        </div>

        <div className="mt-4 space-y-3 text-xs">
          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">Security State:</span>
            <span className="font-mono font-semibold px-2 py-0.5 rounded bg-muted text-foreground">
              {device.securityState}
            </span>
          </div>

          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">Zone:</span>
            <span className="font-mono">{device.zone}</span>
          </div>

          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">IP Address:</span>
            <span className="font-mono">{device.ip}</span>
          </div>

          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">Asset Criticality:</span>
            <span className="font-mono font-semibold text-foreground">{device.assetCriticality}</span>
          </div>

          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">Operational Risk:</span>
            <span className="font-mono font-bold text-foreground">
              {device.riskScore.toFixed(1)} / 100.0 [{device.riskLevel}]
            </span>
          </div>

          <div className="py-2">
            <span className="text-muted-foreground block mb-1">Listening Services & Ports:</span>
            <div className="flex flex-wrap gap-1">
              {device.services.map((srv, idx) => (
                <span key={idx} className="px-2 py-0.5 rounded bg-primary/10 text-primary font-mono text-[11px]">
                  {srv} :{device.openPorts[idx] || "—"}
                </span>
              ))}
            </div>
          </div>

          <div className="py-2">
            <span className="text-muted-foreground block mb-1">Active Vulnerabilities:</span>
            {device.vulnerabilities.length > 0 ? (
              <div className="space-y-1">
                {device.vulnerabilities.map((v, i) => (
                  <div key={i} className="px-2 py-1 rounded bg-destructive/15 text-destructive font-mono text-[11px]">
                    ⚠ {v}
                  </div>
                ))}
              </div>
            ) : (
              <span className="text-[11px] text-muted-foreground italic">No active CVEs registered</span>
            )}
          </div>
        </div>
      </div>

      <div className="pt-4 border-t border-border">
        {device.securityState !== "ISOLATED" && onIsolate && (
          <button
            onClick={() => onIsolate(device.deviceId)}
            className="w-full py-2 rounded bg-destructive text-destructive-foreground hover:bg-destructive/90 text-xs font-semibold"
          >
            Quarantine & Isolate Host
          </button>
        )}
      </div>
    </aside>
  );
};