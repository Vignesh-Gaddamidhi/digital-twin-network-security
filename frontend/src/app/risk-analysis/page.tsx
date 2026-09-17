"use client";

import React from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Flame, ShieldAlert, Activity, ArrowUpRight } from "lucide-react";

export default function RiskAnalysisPage() {
  const dials = [
    { label: "Threat (P)", score: "0.98", val: 98, color: "text-cyber-cyan", border: "border-cyber-cyan" },
    { label: "Criticality (C)", score: "1.00", val: 100, color: "text-cyber-amber", border: "border-cyber-amber" },
    { label: "Vulnerability (V)", score: "0.80", val: 80, color: "text-cyber-amber", border: "border-cyber-amber" },
    { label: "Impact (I)", score: "1.00", val: 100, color: "text-cyber-amber", border: "border-cyber-amber" },
  ];

  const assets = [
    { id: "WEB-01", name: "web-01.dmz.internal", p: 0.98, c: 1.00, v: 0.80, i: 1.00, score: 78.4, sev: "HIGH" },
    { id: "DB-01", name: "db-01.database.internal", p: 0.85, c: 1.00, v: 0.90, i: 1.00, score: 76.5, sev: "HIGH" },
    { id: "CLIENT-01", name: "client-01.corp.internal", p: 0.45, c: 0.50, v: 0.60, i: 0.40, score: 54.0, sev: "MEDIUM" },
    { id: "EDGE-FW-01", name: "edge-fw-01.perimeter", p: 0.20, c: 0.90, v: 0.20, i: 0.80, score: 28.8, sev: "LOW" },
  ];

  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200 font-mono">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Quantitative Risk Command Center" />

        <div className="flex-1 p-6 flex flex-col space-y-6 overflow-y-auto">
          {/* Mathematical Formula Banner */}
          <div className="glass-panel p-4 rounded-xl border border-slate-800 text-center space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-bold">Canonical Scoring Engine</span>
            <div className="text-base font-extrabold text-white">
              Risk = Threat Probability (P) &times; Asset Criticality (C) &times; Vulnerability (V) &times; Attack Impact (I)
            </div>
          </div>

          {/* 4 Circular Glowing Telemetry Dials */}
          <div className="glass-panel p-6 rounded-xl border border-slate-800 flex items-center justify-around">
            {dials.map((d, i) => (
              <React.Fragment key={d.label}>
                <div className="flex flex-col items-center space-y-2">
                  <div className={`w-28 h-28 rounded-full border-4 ${d.border} flex flex-col items-center justify-center bg-obsidian-900 shadow-cyan-glow`}>
                    <span className={`text-2xl font-black ${d.color}`}>{d.score}</span>
                    <span className="text-[9px] text-slate-500 font-bold">{d.label}</span>
                  </div>
                </div>
                {i < 3 && <span className="text-xl font-bold text-slate-600">&times;</span>}
              </React.Fragment>
            ))}

            <div className="pl-6 border-l border-slate-800 text-center">
              <span className="text-[10px] text-slate-500 block font-bold">COMPOSITE SCORE</span>
              <div className="text-3xl font-black text-cyber-crimson shadow-crimson-glow mt-1">78.4</div>
              <span className="px-2 py-0.5 rounded bg-cyber-crimson/20 border border-cyber-crimson/40 text-cyber-crimson font-bold text-[10px]">
                HIGH RISK
              </span>
            </div>
          </div>

          {/* Per-Asset Risk Ranking Table */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">Per-Asset Exposure Ranking Table</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="text-[10px] text-slate-400 uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Asset Hostname</th>
                    <th className="py-2.5 px-3">Threat (P)</th>
                    <th className="py-2.5 px-3">Criticality (C)</th>
                    <th className="py-2.5 px-3">Vulnerability (V)</th>
                    <th className="py-2.5 px-3">Impact (I)</th>
                    <th className="py-2.5 px-3">Composite Score</th>
                    <th className="py-2.5 px-3 text-right">Exposure Level</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {assets.map((a) => (
                    <tr key={a.id} className="hover:bg-obsidian-800/60 transition">
                      <td className="py-3 px-3 font-bold text-slate-200">{a.name}</td>
                      <td className="py-3 px-3 text-cyber-cyan">{a.p.toFixed(2)}</td>
                      <td className="py-3 px-3 text-slate-300">{a.c.toFixed(2)}</td>
                      <td className="py-3 px-3 text-slate-300">{a.v.toFixed(2)}</td>
                      <td className="py-3 px-3 text-slate-300">{a.i.toFixed(2)}</td>
                      <td className="py-3 px-3">
                        <div className="flex items-center space-x-2">
                          <div className="w-24 bg-slate-800 h-2 rounded-full overflow-hidden">
                            <div 
                              className={`h-full ${a.score > 70 ? "bg-cyber-crimson" : a.score > 40 ? "bg-cyber-amber" : "bg-cyber-emerald"}`}
                              style={{ width: `${a.score}%` }}
                            />
                          </div>
                          <span className="font-bold">{a.score}</span>
                        </div>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <span className={`px-2 py-0.5 rounded font-black text-[10px] border ${
                          a.sev === "HIGH" ? "bg-cyber-crimson/20 border-cyber-crimson/40 text-cyber-crimson" :
                          a.sev === "MEDIUM" ? "bg-cyber-amber/20 border-cyber-amber/40 text-cyber-amber" :
                          "bg-cyber-emerald/20 border-cyber-emerald/40 text-cyber-emerald"
                        }`}>
                          {a.sev}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}