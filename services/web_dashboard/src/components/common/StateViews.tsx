import React from "react";
import { ComponentUiState } from "../../types/dashboard";

interface StateViewProps {
  state: ComponentUiState;
  title?: string;
  message?: string;
  onRetry?: () => void;
  children?: React.ReactNode;
}

export const StateView: React.FC<StateViewProps> = ({ state, title, message, onRetry, children }) => {
  if (state === "SUCCESS") return <>{children}</>;

  if (state === "LOADING") {
    return (
      <div className="p-8 border border-border rounded-lg bg-card/40 flex flex-col items-center justify-center gap-3">
        <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        <span className="text-xs text-muted-foreground font-mono">{title || "Loading telemetry data..."}</span>
      </div>
    );
  }

  if (state === "ERROR") {
    return (
      <div className="p-6 border border-destructive/30 rounded-lg bg-destructive/10 text-destructive flex flex-col items-center gap-3">
        <span className="font-semibold text-sm">{title || "Failed to Load Component"}</span>
        <span className="text-xs text-center">{message || "The Digital Twin telemetry stream was interrupted."}</span>
        {onRetry && (
          <button
            onClick={onRetry}
            className="text-xs px-3 py-1.5 rounded bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            Retry Sync
          </button>
        )}
      </div>
    );
  }

  if (state === "OFFLINE") {
    return (
      <div className="p-6 border border-border rounded-lg bg-muted/30 text-muted-foreground text-center">
        <span className="text-xs font-mono">SIMULATION STREAM OFFLINE</span>
      </div>
    );
  }

  return <>{children}</>;
};