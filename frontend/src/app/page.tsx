"use client";

import React, { useState } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { 
  ShieldAlert, Activity, Network, AlertOctagon, ArrowUpRight 
} from "lucide-react";

export default function DashboardPage() {
  const { setSelectedDeviceId } = useSoc();
  const [metrics] = useState<any>({
    totalAssets: 6,
    isolatedAssets: 1,
    globalThreatPct: 78,
    activeThreats: 4,
    criticalAlerts: 3,
    openIncidents: 2,
    networkHealthPct: 77.4,
    compositeRiskScore: 78.4,
    severities: { CRITICAL: 4, HIGH: 8, MEDIUM: 9, LOW: 3 },
    highestRiskDevices: [
      { id: "WEB-01", hostname: "web-01.dmz.internal", score: 85.0, tier: "CRITICAL", ip: "10.0.2.99" },
      { id: "DB-01", hostname: "db-01.database.internal", score: 78.4, tier: "HIGH", ip: "10.0.3.10" },
      { id: "CLIENT-01", hostname: "client-01.corp.internal", score: 62.1, tier: "MEDIUM", ip: "10.0.1.25" }
    ],
    recentFeed: [
      { time: "10:14:22.054", type: "DETECTION", label: "Suricata ET DOS HTTP Slowloris Inbound Attempt SID:200142", target: "WEB-01", sev: "CRITICAL" },
      { time: "10:14:24.812", type: "PREDICTION", label: "Ensemble ML Model: LATERAL_MOVEMENT (96.4% confidence)", target: "WEB-01", sev: "CRITICAL" },
      { time: "10:14:26.120", type: "RISK", label: "Composite Risk Score (P*C*V*I) elevated to 78.4", target: "WEB-01", sev: "HIGH" },
      { time: "10:14:30.400", type: "RESPONSE", label: "ISOLATE_DEVICE simulated on WEB-01 [Enforced]", target: "WEB-01", sev: "INFO" },
      { time: "10:14:31.905", type: "INCIDENT", label: "INC-2026-0916-001 updated to INVESTIGATING by Sarah Connor", target: "DB-01", sev: "HIGH" }
    ]
  });

  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Executive Security Command Center" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          <div className="grid grid-cols-4 gap-4">
            <div className="glass-panel p-4 rounded-xl border border-cyber-crimson/30 relative overflow-hidden shadow-crimson-glow">
              <div className="flex justify-between items-center text-xs font-mono font-semibold text-slate-400">
                <span>GLOBAL THREAT LEVEL</span>
                <ShieldAlert className="w-4 h-4 text-cyber-crimson" />
              </div>
              <div className="flex items-baseline space-x-2 mt-2">
                <span className="text-3xl font-mono font-black text-cyber-crimson">
                  {metrics.globalThreatPct}%
                </span>
                <span className="text-[10px] font-mono font-black text-cyber-crimson px-1.5 py-0.5 rounded bg-cyber-crimson/20 border border-cyber-crimson/40">
                  CRIMSON ALERT
                </span>
              </div>
              <div className="text-[10px] font-mono text-slate-400 mt-1">Status: High Lateral Movement Probability</div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-slate-800">
              <div className="flex justify-between items-center text-xs font-mono font-semibold text-slate-400">
                <span>ACTIVE ASSETS</span>
                <Network className="w-4 h-4 text-cyber-cyan" />
              </div>
              <div className="flex items-baseline space-x-2 mt-2">
                <span className="text-3xl font-mono font-black text-white">{metrics.totalAssets}</span>
                <span className="text-xs font-mono text-slate-400">Monitored</span>
              </div>
              <div className="text-[11px] font-mono text-cyber-crimson font-bold mt-1">
                {metrics.isolatedAssets} Asset Safely Isolated (Simulation)
              </div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-slate-800">
              <div className="flex justify-between items-center text-xs font-mono font-semibold text-slate-400">
                <span>OPEN INCIDENTS</span>
                <AlertOctagon className="w-4 h-4 text-cyber-amber" />
              </div>
              <div className="flex items-baseline space-x-2 mt-2">
                <span className="text-3xl font-mono font-black text-cyber-amber">{metrics.openIncidents}</span>
                <span className="text-xs font-mono text-slate-400">Cases</span>
              </div>
              <div className="text-[11px] font-mono text-cyber-cyan font-semibold mt-1">
                1 Investigating • 1 Escalated
              </div>
            </div>

            <div className="glass-panel p-4 rounded-xl border border-slate-800">
              <div className="flex justify-between items-center text-xs font-mono font-semibold text-slate-400">
                <span>SYSTEM INTEGRITY</span>
                <Activity className="w-4 h-4 text-cyber-emerald" />
              </div>
              <div className="flex items-baseline space-x-2 mt-2">
                <span className="text-3xl font-mono font-black text-cyber-emerald">
                  {metrics.networkHealthPct}%
                </span>
                <span className="text-[10px] font-mono text-slate-400 font-bold">OPERATIONAL</span>
              </div>
              <div className="text-[11px] font-mono text-slate-400 mt-1">
                Dual-Horizon Forecast Active
              </div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-6">
            <div className="glass-panel p-5 rounded-xl border border-slate-800 col-span-2 flex flex-col justify-between">
              <div className="flex justify-between items-center mb-3">
                <h3 className="font-mono font-bold text-white text-sm">Real-Time Bandwidth Telemetry (PPS / Throughput)</h3>
                <span className="text-[10px] font-mono font-bold text-cyber-cyan bg-cyber-cyan/10 border border-cyber-cyan/30 px-2 py-0.5 rounded">
                  240 MB/s PEAK
                </span>
              </div>
              <div className="h-44 w-full flex items-end justify-between space-x-1.5 pt-4 px-2 bg-obsidian-900/60 rounded-lg border border-slate-800/80">
                {[35, 45, 60, 40, 80, 120, 95, 140, 110, 180, 240, 190, 150, 210, 175, 130, 90, 110, 85, 95].map((val, idx) => (
                  <div key={idx} className="flex-1 flex flex-col items-center">
                    <div 
                      className={`w-full rounded-t transition-all duration-300 ${
                        val > 180 ? "bg-cyber-crimson shadow-crimson-glow" :
                        val > 100 ? "bg-cyber-cyan shadow-cyan-glow" : "bg-slate-700"
                      }`}
                      style={{ height: `${(val / 240) * 140}px` }}
                    ></div>
                  </div>
                ))}
              </div>
              <div className="flex justify-between text-[10px] font-mono text-slate-500 pt-3">
                <span>00:00:00</span>
                <span>06:00:00</span>
                <span>12:00:00</span>
                <span>18:00:00</span>
                <span>NOW (LIVE TELEMETRY)</span>
              </div>
            </div>

            <div className="glass-panel p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
              <div className="flex justify-between items-center mb-3">
                <h3 className="font-mono font-bold text-white text-sm">High-Risk Twin Assets</h3>
                <span className="text-[10px] font-mono text-slate-400">P x C x V x I</span>
              </div>
              <div className="space-y-2.5">
                {metrics.highestRiskDevices.map((d: any) => (
                  <div key={d.id} className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-obsidian-800/60 hover:border-cyber-cyan/40 transition">
                    <div>
                      <Link 
                        href="/network-twin" 
                        onClick={() => setSelectedDeviceId(d.id)}
                        className="font-mono font-bold text-xs text-cyber-cyan hover:underline flex items-center space-x-1"
                      >
                        <span>{d.hostname}</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </Link>
                      <div className="text-[10px] text-slate-500 font-mono font-semibold">{d.id} • {d.ip}</div>
                    </div>
                    <div className="text-right">
                      <span className={`text-[11px] font-mono px-2 py-0.5 rounded font-black ${
                        d.tier === "CRITICAL" ? "bg-cyber-crimson/20 border border-cyber-crimson/40 text-cyber-crimson shadow-crimson-glow" :
                        "bg-cyber-amber/20 border border-cyber-amber/40 text-cyber-amber"
                      }`}>
                        {d.score}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
              <Link href="/risk-analysis" className="text-center text-xs font-mono font-bold text-cyber-cyan hover:underline pt-3 border-t border-slate-800 flex items-center justify-center space-x-1">
                <span>Open Quantitative Risk Engine</span>
                <span>&rarr;</span>
              </Link>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-xl border border-slate-800">
            <div className="flex justify-between items-center mb-3">
              <h3 className="font-mono font-bold text-white text-sm">Live Microsecond Chronological Activity Feed</h3>
              <span className="text-[10px] font-mono text-cyber-cyan">Redis Streams Buffer Active</span>
            </div>
            <div className="space-y-2">
              {metrics.recentFeed.map((item: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between text-xs p-3 rounded-lg border border-slate-800/70 bg-obsidian-800/40 hover:bg-obsidian-800/80 transition font-mono">
                  <div className="flex items-center space-x-3">
                    <span className="text-slate-500 text-[11px]">{item.time}</span>
                    <span className={`text-[10px] font-black px-2 py-0.5 rounded border ${
                      item.sev === "CRITICAL" ? "bg-cyber-crimson/20 border-cyber-crimson/40 text-cyber-crimson" :
                      item.sev === "HIGH" ? "bg-cyber-amber/20 border-cyber-amber/40 text-cyber-amber" :
                      "bg-cyber-cyan/20 border-cyber-cyan/40 text-cyber-cyan"
                    }`}>
                      {item.type}
                    </span>
                    <span className="text-slate-200 font-semibold">{item.label}</span>
                  </div>
                  <span className="text-cyber-cyan text-xs font-bold">{item.target}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}