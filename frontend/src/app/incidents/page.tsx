"use client";

import React from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { AlertOctagon, ArrowUpRight, ShieldAlert, CheckCircle2 } from "lucide-react";

export default function IncidentsPage() {
  const columns = [
    { title: "NEW", count: 1, border: "border-cyber-cyan/40" },
    { title: "INVESTIGATING", count: 1, border: "border-cyber-amber/40" },
    { title: "CONTAINED", count: 2, border: "border-purple-600/40" },
    { title: "RESOLVED", count: 12, border: "border-cyber-emerald/40" },
  ];

  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200 font-mono">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Security Operations SOAR Workspace" />

        <div className="flex-1 p-6 flex flex-col space-y-4 overflow-hidden">
          {/* Top Summary Status Ribbon */}
          <div className="glass-panel p-4 rounded-xl border border-slate-800 flex justify-between items-center text-xs">
            <div className="flex items-center space-x-6">
              <span>Open Cases: <b className="text-cyber-crimson">2</b></span>
              <span>Contained: <b className="text-purple-400">2</b></span>
              <span>Resolved: <b className="text-cyber-emerald">12</b></span>
            </div>
            <div className="text-[10px] text-slate-400">
              Assigned Lead: <span className="text-cyber-cyan font-bold">Sarah Connor</span>
            </div>
          </div>

          {/* Kanban Board Columns */}
          <div className="flex-1 grid grid-cols-4 gap-4 overflow-hidden">
            {/* Column: NEW */}
            <div className="glass-panel rounded-xl border border-slate-800 flex flex-col p-3 space-y-3">
              <div className="flex justify-between items-center border-b border-slate-800 pb-2 text-xs font-bold text-cyber-cyan">
                <span>NEW (1)</span>
              </div>
              <div className="p-3 rounded-lg bg-obsidian-900 border border-slate-800 space-y-2 text-xs">
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40 font-black">
                  HIGH
                </span>
                <div className="font-bold text-white">INC-2026-0916-002</div>
                <div className="text-[11px] text-slate-400">Port sweep detected on corporate subnet</div>
              </div>
            </div>

            {/* Column: INVESTIGATING */}
            <div className="glass-panel rounded-xl border border-cyber-crimson/40 shadow-crimson-glow flex flex-col p-3 space-y-3">
              <div className="flex justify-between items-center border-b border-slate-800 pb-2 text-xs font-bold text-cyber-crimson">
                <span>INVESTIGATING (1)</span>
              </div>
              <div className="p-3.5 rounded-lg bg-obsidian-800/80 border border-cyber-crimson/50 space-y-2.5 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyber-crimson/20 text-cyber-crimson border border-cyber-crimson/40 font-black">
                    CRITICAL
                  </span>
                  <span className="text-[10px] text-slate-400">3 Alerts</span>
                </div>
                <div className="font-bold text-white">INC-2026-0916-001</div>
                <div className="text-[11px] text-slate-300">Lateral Movement Infiltration toward DB Tier</div>
                <div className="pt-2 border-t border-slate-700/80 flex justify-between items-center">
                  <span className="text-[10px] text-slate-400">Operator: Sarah Connor</span>
                  <Link 
                    href="/incidents/INC-2026-0916-001" 
                    className="text-[10px] text-cyber-cyan font-bold hover:underline flex items-center space-x-1"
                  >
                    <span>17-Link Lineage</span>
                    <span>&rarr;</span>
                  </Link>
                </div>
              </div>
            </div>

            {/* Column: CONTAINED */}
            <div className="glass-panel rounded-xl border border-slate-800 flex flex-col p-3 space-y-3">
              <div className="flex justify-between items-center border-b border-slate-800 pb-2 text-xs font-bold text-purple-400">
                <span>CONTAINED (2)</span>
              </div>
              <div className="p-3 rounded-lg bg-obsidian-900 border border-slate-800 space-y-2 text-xs opacity-75">
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-900/40 text-purple-300 border border-purple-700 font-bold">
                  SIMULATED
                </span>
                <div className="font-bold text-white">INC-2026-0915-088</div>
                <div className="text-[10px] text-slate-400">WEB-01 Isolated from Corp segment</div>
              </div>
            </div>

            {/* Column: RESOLVED */}
            <div className="glass-panel rounded-xl border border-slate-800 flex flex-col p-3 space-y-3">
              <div className="flex justify-between items-center border-b border-slate-800 pb-2 text-xs font-bold text-cyber-emerald">
                <span>RESOLVED (12)</span>
              </div>
              <div className="p-3 rounded-lg bg-obsidian-900 border border-slate-800 space-y-1 text-xs opacity-50">
                <div className="font-bold text-slate-300">INC-2026-0914-042</div>
                <div className="text-[10px] text-slate-500">Heuristic DNS Tunnel False Positive</div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}