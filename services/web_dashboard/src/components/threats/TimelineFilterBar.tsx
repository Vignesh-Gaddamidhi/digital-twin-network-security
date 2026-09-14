import React from "react";
import { TimelineCategory } from "../../types/timeline";

interface TimelineFilterBarProps {
  activeCategory: TimelineCategory;
  activeSeverity: string;
  searchTerm: string;
  onSelectCategory: (cat: TimelineCategory) => void;
  onSelectSeverity: (sev: string) => void;
  onSearchChange: (term: string) => void;
}

const CATEGORIES: { id: TimelineCategory; label: string }[] = [
  { id: "ALL", label: "All Events" },
  { id: "THREATS", label: "Threats" },
  { id: "ALERTS", label: "Alerts" },
  { id: "PREDICTIONS", label: "Predictions" },
  { id: "RISK", label: "Risk" },
  { id: "ATTACK_PATHS", label: "Attack Paths" },
  { id: "IDS", label: "IDS" }
];

export const TimelineFilterBar: React.FC<TimelineFilterBarProps> = ({
  activeCategory,
  activeSeverity,
  searchTerm,
  onSelectCategory,
  onSelectSeverity,
  onSearchChange
}) => {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 p-3 border-b border-border bg-card/60 backdrop-blur-sm">
      <div className="flex items-center gap-1 overflow-x-auto py-1">
        {CATEGORIES.map((c) => (
          <button
            key={c.id}
            onClick={() => onSelectCategory(c.id)}
            className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-colors whitespace-nowrap ${
              activeCategory === c.id
                ? "bg-primary text-primary-foreground"
                : "bg-muted/50 text-muted-foreground hover:bg-muted hover:text-foreground"
            }`}
          >
            {c.label}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-2 text-xs font-mono">
        <select
          value={activeSeverity}
          onChange={(e) => onSelectSeverity(e.target.value)}
          className="px-2.5 py-1 rounded border border-border bg-background text-foreground text-xs"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <input
          type="text"
          placeholder="Filter description / ID..."
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          className="px-3 py-1 rounded border border-border bg-background text-foreground text-xs w-44 focus:ring-1 focus:ring-primary"
        />
      </div>
    </div>
  );
};