import React from "react";
import { ThreatTimelineEvent } from "../../types/timeline";
import { NavigationRouteId } from "../../types/dashboard";

interface EventDetailDrawerProps {
  event: ThreatTimelineEvent | null;
  onClose: () => void;
  onNavigate: (route: NavigationRouteId) => void;
}

export const EventDetailDrawer: React.FC<EventDetailDrawerProps> = ({ event, onClose, onNavigate }) => {
  if (!event) return null;

  const severityColors = {
    LOW: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
    MEDIUM: "bg-amber-500/15 text-amber-500 border-amber-500/30",
    HIGH: "bg-orange-500/15 text-orange-500 border-orange-500/30",
    CRITICAL: "bg-destructive/15 text-destructive border-destructive/30"
  };

  return (
    <aside className="fixed top-16 right-0 w-88 h-[calc(100vh-4rem)] border-l border-border bg-card/95 backdrop-blur-md shadow-2xl z-40 p-4 flex flex-col justify-between overflow-y-auto">
      <div>
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-foreground">{event.eventId}</span>
              <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${severityColors[event.severity]}`}>
                {event.severity}
              </span>
            </div>
            <span className="text-[11px] text-muted-foreground font-mono">{event.timeLabel} ({event.timestamp})</span>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground">
            ✕
          </button>
        </div>

        <div className="mt-4 space-y-3 text-xs">
          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">Category:</span>
            <span className="font-mono font-semibold text-foreground">{event.category}</span>
          </div>

          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">Detection Source:</span>
            <span className="font-mono">{event.detectionSource}</span>
          </div>

          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">Endpoints:</span>
            <span className="font-mono">
              {event.sourceDevice} {event.destinationDevice ? `-> ${event.destinationDevice}` : ""}
            </span>
          </div>

          <div className="flex justify-between py-1 border-b border-border/50">
            <span className="text-muted-foreground">Protocol & Port:</span>
            <span className="font-mono">{event.protocol} {event.port ? `:${event.port}` : ""}</span>
          </div>

          {event.riskScore !== undefined && (
            <div className="flex justify-between py-1 border-b border-border/50">
              <span className="text-muted-foreground">Calculated Risk:</span>
              <strong className="font-mono text-foreground">{event.riskScore.toFixed(1)} / 100.0</strong>
            </div>
          )}

          {event.confidence !== undefined && (
            <div className="flex justify-between py-1 border-b border-border/50">
              <span className="text-muted-foreground">Classifier Confidence:</span>
              <span className="font-mono">{(event.confidence * 100).toFixed(1)}%</span>
            </div>
          )}

          <div className="py-2">
            <span className="text-muted-foreground block mb-1">Description:</span>
            <p className="text-foreground leading-relaxed bg-muted/20 p-2 rounded border border-border/60">
              {event.description}
            </p>
          </div>

          {event.evidenceText && (
            <div className="py-2">
              <span className="text-muted-foreground block mb-1">Forensic Evidence:</span>
              <p className="text-foreground text-[11px] font-mono bg-muted/40 p-2 rounded border border-border">
                {event.evidenceText}
              </p>
            </div>
          )}
        </div>
      </div>

      <div className="pt-4 border-t border-border space-y-2">
        {event.predictionId && (
          <button
            onClick={() => onNavigate("predictions")}
            className="w-full py-2 rounded bg-primary text-primary-foreground hover:bg-primary/90 text-xs font-semibold flex items-center justify-center gap-1.5"
          >
            <span>Explain with XAI (SHAP) →</span>
          </button>
        )}

        {event.pathId && (
          <button
            onClick={() => onNavigate("attack-paths")}
            className="w-full py-2 rounded bg-amber-500 text-amber-950 hover:bg-amber-400 text-xs font-semibold flex items-center justify-center gap-1.5"
          >
            <span>Inspect Attack Path [{event.pathId}] →</span>
          </button>
        )}
      </div>
    </aside>
  );
};