"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { 
  Play, Pause, RotateCcw, Square, FastForward, 
  Terminal, ShieldAlert, Cpu, Flame, CheckCircle2, Sliders
} from "lucide-react";

export default function AttackSimulationPage() {
  const { setSelectedDeviceId } = useSoc();
  const [selectedScenario, setSelectedScenario] = useState("PORT_SCAN");
  const [simStatus, setSimStatus] = useState<"IDLE" | "RUNNING" | "PAUSED" | "STOPPED">("IDLE");
  const [tickInterval, setTickInterval] = useState(100);
  const [speedMultiplier, setSpeedMultiplier] = useState(1.0);
  const [horizonSeconds, setHorizonSeconds] = useState(30);
  const [simLogs, setSimLogs] = useState<string[]>([
    "[SYSTEM] Attack Simulation Engine initialized (Sandbox Isolated)",
    "[READY] 13 Synthetic attack archetypes loaded into runner"
  ]);

  const scenarios = [
    { id: "NORMAL", name: "Normal Baseline Network", category: "BENIGN" },
    { id: "TRAFFIC_SPIKE", name: "Benign E-Commerce Traffic Spike", category: "VOLUMETRIC" },
    { id: "CONNECTION_ANOMALY", name: "Connection Anomaly Probe", category: "ANOMALY" },
    { id: "PORT_SCAN", name: "TCP SYN Port Discovery", category: "RECONNAISSANCE" },
    { id: "BRUTE_FORCE_LIKE", name: "SSH Credential Brute Force", category: "CREDENTIAL_ACCESS" },
    { id: "DOS_LIKE", name: "HTTP Slowloris / SYN Saturation", category: "DENIAL_OF_SERVICE" },
    { id: "DNS_ANOMALY", name: "DNS Amplification & Fast Flux", category: "COMMAND_AND_CONTROL" },
    { id: "BEACONING", name: "Periodic C2 Heartbeat Beacon", category: "COMMAND_AND_CONTROL" },
    { id: "LATERAL_MOVEMENT_LIKE", name: "SMB/RPC Pivot to Database", category: "LATERAL_MOVEMENT" },
    { id: "EXFILTRATION_LIKE", name: "Encrypted DNS Tunnel Exfiltration", category: "EXFILTRATION" }
  ];

  const handleStart = () => {
    setSimStatus("RUNNING");
    setSimLogs((prev) => [
      ...prev,
      `[LAUNCH] Scenario '${selectedScenario}' initiated (Horizon: ${horizonSeconds}s, Speed: ${speedMultiplier}x)`,
      `[SIM] Emitting synthetic flow telemetry across virtual interfaces...`
    ]);
  };

  const handlePause = () => {
    setSimStatus("PAUSED");
    setSimLogs((prev) => [...prev, `[PAUSE] Simulation clock suspended at active tick.`]);
  };

  const handleStop = () => {
    setSimStatus("STOPPED");
    setSimLogs((prev) => [...prev, `[STOP] Simulation halted. Digital Twin graph baseline restored.`]);
  };

  const handleReset = () => {
    setSimStatus("IDLE");
    setSimLogs([
      "[SYSTEM] Attack Simulation Engine initialized (Sandbox Isolated)",
      "[RESET] Telemetry counters cleared to tick #0"
    ]);
  };

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Synthetic Attack Simulation Sandbox" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Top Playback Toolbar */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-bold ${
                simStatus === "RUNNING" ? "bg-emerald-100 text-emerald-700 animate-pulse" :
                simStatus === "PAUSED" ? "bg-amber-100 text-amber-700" : "bg-slate-100 text-slate-600"
              }`}>
                STATUS: {simStatus}
              </span>
              <button
                onClick={handleStart}
                disabled={simStatus === "RUNNING"}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-bold rounded-lg transition"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Start</span>
              </button>
              <button
                onClick={handlePause}
                disabled={simStatus !== "RUNNING"}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-700 text-xs font-bold rounded-lg transition"
              >
                <Pause className="w-3.5 h-3.5" />
                <span>Pause</span>
              </button>
              <button
                onClick={handleStop}
                disabled={simStatus === "IDLE" || simStatus === "STOPPED"}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-red-50 hover:bg-red-100 disabled:opacity-50 text-red-600 text-xs font-bold rounded-lg transition border border-red-200"
              >
                <Square className="w-3.5 h-3.5" />
                <span>Stop</span>
              </button>
              <button
                onClick={handleReset}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-lg transition"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset</span>
              </button>
            </div>

            {/* Simulation Parameter Sliders */}
            <div className="flex items-center space-x-6 text-xs text-slate-600 font-semibold">
              <div className="flex items-center space-x-2">
                <span>Speed:</span>
                <select
                  value={speedMultiplier}
                  onChange={(e) => setSpeedMultiplier(parseFloat(e.target.value))}
                  className="bg-slate-50 border border-slate-200 rounded px-2 py-1 text-xs font-mono"
                >
                  <option value={0.5}>0.5x</option>
                  <option value={1.0}>1.0x</option>
                  <option value={2.0}>2.0x</option>
                  <option value={5.0}>5.0x</option>
                </select>
              </div>
              <div className="flex items-center space-x-2">
                <span>Prediction Horizon:</span>
                <span className="font-mono font-bold text-blue-600">{horizonSeconds}s</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-6">
            {/* Scenario Selection Grid */}
            <div className="col-span-2 bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-3">
              <h3 className="font-bold text-slate-900 text-sm">Select Synthetic Attack Scenario</h3>
              <div className="grid grid-cols-2 gap-3">
                {scenarios.map((sc) => (
                  <div
                    key={sc.id}
                    onClick={() => setSelectedScenario(sc.id)}
                    className={`p-3 rounded-lg border text-xs cursor-pointer transition flex items-center justify-between ${
                      selectedScenario === sc.id
                        ? "border-blue-600 bg-blue-50/50 shadow-sm ring-1 ring-blue-500"
                        : "border-slate-200 hover:border-slate-300 bg-white"
                    }`}
                  >
                    <div>
                      <div className="font-bold text-slate-900">{sc.name}</div>
                      <div className="text-[10px] text-slate-400 font-mono mt-0.5">{sc.category}</div>
                    </div>
                    <span className="text-[9px] font-mono px-1.5 py-0.5 bg-slate-100 rounded text-slate-500 font-bold">
                      {sc.id}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Live Scenario Terminal Stream */}
            <div className="bg-slate-900 rounded-xl p-5 text-emerald-400 font-mono text-xs flex flex-col justify-between shadow-sm">
              <div>
                <div className="text-white font-bold mb-3 border-b border-slate-800 pb-2 flex justify-between items-center">
                  <span>Simulation Telemetry Feed</span>
                  <span className="text-[10px] text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                    ISOLATED
                  </span>
                </div>
                <div className="space-y-1.5 overflow-y-auto max-h-80 text-[11px]">
                  {simLogs.map((log, idx) => (
                    <div key={idx} className={log.includes("[LAUNCH]") ? "text-amber-300" : log.includes("[STOP]") ? "text-red-300" : ""}>
                      {log}
                    </div>
                  ))}
                </div>
              </div>
              <div className="text-[10px] text-slate-500 border-t border-slate-800 pt-2 mt-4">
                Synthetic traffic strictly bound to Digital Twin memory buffers.
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}