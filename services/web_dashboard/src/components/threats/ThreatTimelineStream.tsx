import React from "react";
import { ThreatTimelineEvent } from "../../types/timeline";

interface ThreatTimelineStreamProps {
  events: ThreatTimelineEvent[];
  selectedEventId?: string;
  onSelectEvent: (event: ThreatTimelineEvent) => void;
}

export const ThreatTimelineStream: React.FC<ThreatTimelineStreamProps> = ({
  events,
  selectedEventId,
  onSelectEvent
}) => {
  const severityBadge = {
    LOW: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
    MEDIUM: "bg-amber-500/10 text-amber-500 border-amber-500/20",
    HIGH: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    CRITICAL: "bg-destructive/10 text-destructive border-destructive/20"
  };

  if (events.length === 0) {
    return (
      <div className="p-12 text-center text-xs font-mono text-muted-foreground">
        No security events match the active criteria.
      </div>
    );
  }

  return (
    <div className="divide-y divide-border/60">
      {events.map((ev) => {
        const isSelected = selectedEventId === ev.eventId;
        return (
          <div
            key={ev.eventId}
            onClick={() => onSelectEvent(ev)}
            className={`p-3.5 flex items-start gap-4 hover:bg-muted/30 cursor-pointer transition-colors ${
              isSelected ? "bg-accent/40 border-l-2 border-primary" : ""
            }`}
          >
            {/* Timestamp Column */}
            <div className="w-20 shrink-0 text-[11px] font-mono text-muted-foreground pt-0.5">
              {ev.timeLabel}
            </div>

            {/* Severity Pill */}
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border shrink-0 ${severityBadge[ev.severity]}`}>
              {ev.severity}
            </span>

            {/* Main Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-semibold text-foreground truncate">
                  {ev.eventType}
                </span>
                <span className="text-[10px] font-mono text-muted-foreground bg-muted px-1.5 py-0.2 rounded">
                  {ev.category}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5 truncate">
                {ev.description}
              </p>
            </div>

            {/* Device & Links Badge */}
            <div className="shrink-0 flex items-center gap-2 text-[11px] font-mono">
              <span className="text-foreground">{ev.sourceDevice}</span>
              {ev.predictionId && (
                <span className="text-[10px] text-primary px-1.5 py-0.5 rounded bg-primary/10 border border-primary/20">
                  XAI
                </span>
              )}
              {ev.pathId && (
                <span className="text-[10px] text-amber-500 px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/20">
                  PATH
                </span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};