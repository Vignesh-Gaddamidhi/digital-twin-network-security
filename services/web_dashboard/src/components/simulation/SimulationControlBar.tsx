import React from "react";
import { SimulationControlState } from "../../types/summary";

interface SimulationControlBarProps {
  state: SimulationControlState;
  onStart: () => void;
  onPause: () => void;
  onStop: () => void;
  onReset: () => void;
  onSelectScenario: (scenario: string) => void;
  onSetSpeed: (speed: number) => void;
}

const AVAILABLE_SCENARIOS = [
  "NORMAL",
  "TRAFFIC_SPIKE",
  "LATERAL_MOVEMENT_LIKE",
  "EXFILTRATION_LIKE",
  "PORT_SCAN",
  "DOS_SATURATION"
];

export const SimulationControlBar: React.FC<SimulationControlBarProps> = ({
  state,
  onStart,
  onPause,
  onStop,
  onReset,
  onSelectScenario,
  onSetSpeed
}) => {
  return (
    <div className="p-3 rounded-lg border border-border bg-card/80 backdrop-blur-sm flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-sky-500 animate-pulse" />
          <span className="text-muted-foreground uppercase">Simulation Engine:</span>
          <strong className="text-foreground font-semibold">{state.status}</strong>
        </div>

        <div className="flex items-center gap-1 border-l border-border pl-3">
          <button
            onClick={onStart}
            disabled={state.status === "RUNNING"}
            className="px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-500 hover:bg-emerald-500/25 disabled:opacity-40"
          >
            ▶ Start
          </button>
          <button
            onClick={onPause}
            disabled={state.status !== "RUNNING"}
            className="px-2.5 py-1 rounded bg-amber-500/15 text-amber-500 hover:bg-amber-500/25 disabled:opacity-40"
          >
            Ⅱ Pause
          </button>
          <button
            onClick={onStop}
            disabled={state.status === "STOPPED"}
            className="px-2.5 py-1 rounded bg-destructive/15 text-destructive hover:bg-destructive/25 disabled:opacity-40"
          >
            ■ Stop
          </button>
          <button
            onClick={onReset}
            className="px-2.5 py-1 rounded bg-muted hover:bg-muted/80 text-foreground"
          >
            ↻ Reset
          </button>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Scenario:</span>
          <select
            value={state.activeScenario}
            onChange={(e) => onSelectScenario(e.target.value)}
            className="px-2.5 py-1 rounded border border-border bg-background text-foreground text-xs"
          >
            {AVAILABLE_SCENARIOS.map((sc) => (
              <option key={sc} value={sc}>{sc}</option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-1 border-l border-border pl-3">
          <span className="text-muted-foreground mr-1">Speed:</span>
          {[1, 2, 5].map((spd) => (
            <button
              key={spd}
              onClick={() => onSetSpeed(spd)}
              className={`px-2 py-0.5 rounded text-[11px] ${
                state.speedMultiplier === spd
                  ? "bg-primary text-primary-foreground font-bold"
                  : "bg-muted text-muted-foreground hover:bg-muted/80"
              }`}
            >
              {spd}x
            </button>
          ))}
        </div>

        <div className="border-l border-border pl-3 text-muted-foreground">
          Elapsed: <span className="text-foreground">{state.elapsedSimulationTime}</span>
        </div>
      </div>
    </div>
  );
};