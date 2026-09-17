"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { 
  Terminal, Play, Pause, Square, RotateCcw, 
  CheckCircle2, Flame, ShieldAlert, Cpu, Activity 
} from "lucide-react";

export default function AttackSimulationPage() {
  const [simState, setSimState] = useState<"IDLE" | "RUNNING" | "PAUSED">("RUNNING");
  const [speed, setSpeed] = useState("2.0x");

  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200 font-mono">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Synthetic Attack Simulation Control Deck" />

        <div className="flex-1 p-6 flex flex-col space-y-6 overflow-y-auto">
          {/* Scenario Launcher Control Deck */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyber-cyan" />
                <span>Scenario Launcher Control Deck</span>
              </h3>
              <span className="text-xs px-2 py-0.5 rounded bg-purple-900/50 border border-purple-700 text-purple-300 font-bold">
                SANDBOX ISOLATION ENFORCED
              </span>
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="col-span-2 space-y-1.5">
                <label className="text-[10px] text-slate-400 uppercase font-bold">Active Attack Scenario Template</label>
                <select className="w-full bg-obsidian-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-cyber-cyan">
                  <option>LATERAL_MOVEMENT_LIKE - Web DMZ to Internal DB (CVE-2026-38408)</option>
                  <option>DOS_LIKE - Slowloris HTTP Connection Starvation Flood</option>
                  <option>PORT_SCAN - Multi-Vector TCP SYN Stealth Sweep</option>
                  <option>EXFILTRATION_LIKE - DNS Tunneling via Perimeter Gateway</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-[10px] text-slate-400 uppercase font-bold">Playback Speed Multiplier</label>
                <div className="flex space-x-2">
                  {["1.0x", "2.0x", "4.0x"].map((s) => (
                    <button
                      key={s}
                      onClick={() => setSpeed(s)}
                      className={`flex-1 py-2 text-xs font-bold rounded-lg border transition ${
                        speed === s ? "bg-cyber-cyan text-obsidian border-cyber-cyan shadow-cyan-glow" : "bg-obsidian-900 text-slate-400 border-slate-800"
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Interactive Playback HUD Controls */}
            <div className="flex space-x-3 pt-2">
              <button 
                onClick={() => setSimState("RUNNING")}
                className="px-5 py-2.5 rounded-lg bg-cyber-cyan/20 border border-cyber-cyan/50 text-cyber-cyan font-bold text-xs flex items-center space-x-2 hover:bg-cyber-cyan/30 shadow-cyan-glow"
              >
                <Play className="w-3.5 h-3.5" />
                <span>START</span>
              </button>
              <button 
                onClick={() => setSimState("PAUSED")}
                className="px-5 py-2.5 rounded-lg bg-cyber-amber/20 border border-cyber-amber/50 text-cyber-amber font-bold text-xs flex items-center space-x-2 hover:bg-cyber-amber/30"
              >
                <Pause className="w-3.5 h-3.5" />
                <span>PAUSE</span>
              </button>
              <button 
                onClick={() => setSimState("IDLE")}
                className="px-5 py-2.5 rounded-lg bg-cyber-crimson/20 border border-cyber-crimson/50 text-cyber-crimson font-bold text-xs flex items-center space-x-2 hover:bg-cyber-crimson/30 shadow-crimson-glow"
              >
                <Square className="w-3.5 h-3.5" />
                <span>STOP</span>
              </button>
              <button 
                onClick={() => setSimState("IDLE")}
                className="px-5 py-2.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 font-bold text-xs flex items-center space-x-2 hover:text-white"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>RESET</span>
              </button>
            </div>
          </div>

          {/* Live Execution Timeline */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Live Execution Timeline</h3>
            <div className="grid grid-cols-3 gap-4 text-xs">
              <div className="p-3.5 rounded-lg bg-cyber-emerald/10 border border-cyber-emerald/40 space-y-1">
                <div className="flex items-center space-x-2 text-cyber-emerald font-bold">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Stage 1: Port Scan</span>
                </div>
                <div className="text-[10px] text-slate-400">Complete • Target: 10.0.2.99</div>
              </div>

              <div className="p-3.5 rounded-lg bg-cyber-crimson/20 border border-cyber-crimson/50 space-y-1 shadow-crimson-glow">
                <div className="flex items-center space-x-2 text-cyber-crimson font-bold">
                  <Flame className="w-4 h-4 animate-pulse" />
                  <span>Stage 2: CVE-2026-RCE</span>
                </div>
                <div className="text-[10px] text-slate-300 font-bold">Success • WEB-01 Compromised</div>
              </div>

              <div className="p-3.5 rounded-lg bg-cyber-amber/10 border border-cyber-amber/40 space-y-1">
                <div className="flex items-center space-x-2 text-cyber-amber font-bold">
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Stage 3: Credential Dump</span>
                </div>
                <div className="text-[10px] text-slate-400">Active • Probing port 3306 on DB-01</div>
              </div>
            </div>
          </div>

          {/* Live Event Log Terminal */}
          <div className="glass-panel rounded-xl border border-slate-800 flex-1 flex flex-col overflow-hidden min-h-[220px]">
            <div className="p-3 border-b border-slate-800 bg-obsidian-900 flex justify-between items-center text-xs">
              <span className="font-bold text-white flex items-center space-x-2">
                <Terminal className="w-3.5 h-3.5 text-cyber-cyan" />
                <span>Live Event Log Terminal</span>
              </span>
              <span className="text-[10px] text-cyber-emerald">Streaming via Redis Bus</span>
            </div>
            <div className="flex-1 p-4 bg-slate-950 font-mono text-[11px] text-slate-300 space-y-1 overflow-y-auto">
              <div>[2026-09-16 10:14:22.045] {"{"}"event": "PORT_SCAN", "src": "10.0.1.25", "dst": "10.0.2.99", "ports": [22, 80, 443, 8080]{"}"}</div>
              <div>[2026-09-16 10:14:23.120] {"{"}"event": "EXPLOIT_PAYLOAD", "target": "WEB-01", "cve": "CVE-2026-38408", "status": "INJECTED"{"}"}</div>
              <div className="text-cyber-crimson font-bold">[2026-09-16 10:14:24.812] {"{"}"alert": "HOST_COMPROMISED", "device": "WEB-01", "state": "COMPROMISED"{"}"}</div>
              <div className="text-cyber-amber">[2026-09-16 10:14:25.040] {"{"}"pivot": "LATERAL_SCAN", "src": "10.0.2.99", "dst": "10.0.3.10:3306", "probe": "INITIATED"{"}"}</div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}