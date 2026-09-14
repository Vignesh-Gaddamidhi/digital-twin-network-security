import React from "react";

interface TopologyControlsProps {
  searchTerm: string;
  selectedZone: string;
  highlightAttackPath: boolean;
  onSearchChange: (val: string) => void;
  onZoneChange: (val: string) => void;
  onToggleHighlight: (val: boolean) => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onReset: () => void;
}

export const TopologyControls: React.FC<TopologyControlsProps> = ({
  searchTerm,
  selectedZone,
  highlightAttackPath,
  onSearchChange,
  onZoneChange,
  onToggleHighlight,
  onZoomIn,
  onZoomOut,
  onReset
}) => {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 p-3 border-b border-border bg-card/60 backdrop-blur-sm">
      <div className="flex items-center gap-2 text-xs">
        <input
          type="text"
          placeholder="Search device by ID / IP..."
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          className="px-3 py-1.5 rounded border border-border bg-background text-foreground text-xs focus:ring-1 focus:ring-primary font-mono w-52"
        />

        <select
          value={selectedZone}
          onChange={(e) => onZoneChange(e.target.value)}
          className="px-2.5 py-1.5 rounded border border-border bg-background text-foreground text-xs font-mono"
        >
          <option value="ALL">All Zones</option>
          <option value="INTERNET">INTERNET</option>
          <option value="DMZ">DMZ</option>
          <option value="INTERNAL">INTERNAL</option>
          <option value="DATABASE">DATABASE</option>
        </select>

        <label className="flex items-center gap-1.5 cursor-pointer select-none font-mono">
          <input
            type="checkbox"
            checked={highlightAttackPath}
            onChange={(e) => onToggleHighlight(e.target.checked)}
            className="rounded text-primary focus:ring-0"
          />
          Highlight Active Attack Path
        </label>
      </div>

      <div className="flex items-center gap-1">
        <button onClick={onZoomIn} className="px-2.5 py-1 rounded bg-muted hover:bg-muted/80 text-xs font-mono font-bold">+</button>
        <button onClick={onZoomOut} className="px-2.5 py-1 rounded bg-muted hover:bg-muted/80 text-xs font-mono font-bold">-</button>
        <button onClick={onReset} className="px-3 py-1 rounded bg-muted hover:bg-muted/80 text-xs font-mono">Fit View</button>
      </div>
    </div>
  );
};