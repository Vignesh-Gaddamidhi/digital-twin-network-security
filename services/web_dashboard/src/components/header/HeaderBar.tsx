import React from "react";
import { SystemHeaderContext } from "../../types/dashboard";

interface HeaderBarProps {
  context: SystemHeaderContext;
  isSidebarOpen: boolean;
  onToggleSidebar: () => void;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({ context, isSidebarOpen, onToggleSidebar }) => {
  return (
    <header className="h-16 w-full border-b border-border bg-card/60 backdrop-blur-md px-4 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          aria-label="Toggle Sidebar"
          className="p-2 rounded-md hover:bg-accent text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <div className="flex flex-col">
          <span className="font-semibold text-sm tracking-wide text-foreground flex items-center gap-2">
            {context.systemTitle}
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border">
              {context.environmentName}
            </span>
          </span>
          <span className="text-xs text-muted-foreground">Scenario: <strong className="text-foreground">{context.activeScenario}</strong></span>
        </div>
      </div>

      <div className="flex items-center gap-4 text-xs font-mono">
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          SYSTEM: {context.systemStatus}
        </div>
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-sky-500/10 text-sky-500 border border-sky-500/20">
          <span className="w-2 h-2 rounded-full bg-sky-500" />
          SIMULATION: {context.simulationState}
        </div>
        <div className="hidden md:block text-muted-foreground">
          SYNC: {context.timestamps.lastUpdated}
        </div>
      </div>
    </header>
  );
};