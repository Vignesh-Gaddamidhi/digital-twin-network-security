"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { 
  ShieldAlert, Activity, Network, Terminal, Cpu, Database, 
  Flame, BellRing, AlertOctagon, ArrowUpRight, ShieldCheck, 
  CheckCircle2, RefreshCw
} from "lucide-react";

export default function DashboardPage() {
  const { setSelectedDeviceId, setSelectedAlertId } = useSoc();
  const [metrics, setMetrics] = useState<any>({
    totalAssets: 24,
    activeThreats: 4,
    criticalAlerts: 3,
    openIncidents: 2,
    networkHealthPct: 77.4,
    compositeRiskScore: 68.5,
    simulationsExecuted: 156,
    severities: { CRITICAL: 4, HIGH: 8, MEDIUM: 9, LOW: 3 },
    incidentStatuses: { OPEN: 2, INVESTIGATING: 1, RESOLVED: 12, CLOSED: 45 },
    highestRiskDevices: [
      { id: "WEB-01", hostname: "web-01.dmz.internal", score: 85.0, tier: "CRITICAL" },
      { id: "DB-01", hostname: "db-01.database.internal", score: 78.4, tier: "HIGH" },
      { id: "CLIENT-01", hostname: "client-01.corp.internal", score: 62.1, tier: "HIGH" }
    ],
    recentFeed: [
      { time: "10:14:22", type: "DETECTION", label: "Suricata ET DOS HTTP Flood detected", target: "WEB-01", sev: "CRITICAL" },
      { time: "10:14:24", type: "PREDICTION", label: "ML Classifier: LATERAL_MOVEMENT (96.4%)", target: "WEB-01", sev: "CRITICAL" },
      { time: "10:14:26", type: "RISK", label: "Composite Risk elevated to 85.0", target: "WEB-01", sev: "HIGH" },
      { time: "10:14:30", type: "RESPONSE", label: "ISOLATE_DEVICE simulated on WEB-01", target: "WEB-01", sev: "INFO" },
      { time: "10:14:31", type: "INCIDENT", label: "Incident INC-0012 updated to INVESTIGATING", target: "DB-01", sev: "HIGH" }
    ]
  });

  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/v1/twin/topology/summary")
      .then((res) => res.json())
      .then((data) => {
        if (data.totalDevices) {
          setMetrics((prev: any) => ({ ...prev, totalAssets: data.totalDevices }));
        }
      })
      .catch(() => {});
  }, []);

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Security Command Center — Overview" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Executive KPI Ribbon */}
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Total Twin Assets</span>
                <Network className="w-4 h-4 text-blue-500" />
              </div>
              <div className="text-2xl font-black text-slate-900 mt-1">{metrics.totalAssets}</div>
              <div className="text-[11px] text-emerald-600 font-semibold mt-1">12 DMZ • 6 Corp • 6 DB</div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Active Threats</span>
                <ShieldAlert className="w-4 h-4 text-red-500" />
              </div>
              <div className="text-2xl font-black text-red-600 mt-1">{metrics.activeThreats}</div>
              <div className="text-[11px] text-slate-400 font-semibold mt-1">4 Malicious • 12 Suspicious</div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Open Incidents</span>
                <AlertOctagon className="w-4 h-4 text-amber-500" />
              </div>
              <div className="text-2xl font-black text-amber-600 mt-1">{metrics.openIncidents}</div>
              <div className="text-[11px] text-blue-600 font-semibold mt-1">1 Investigating • 1 Escalated</div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Network Health</span>
                <Activity className="w-4 h-4 text-emerald-500" />
              </div>
              <div className="text-2xl font-black text-emerald-600 mt-1">{metrics.networkHealthPct}%</div>
              <div className="text-[11px] text-amber-600 font-semibold mt-1">Elevated risk detected</div>
            </div>
          </div>

          {/* Threat Severity & Risk Analysis Grid */}
          <div className="grid grid-cols-3 gap-6">
            {/* Threat Severity Breakdown */}
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between">
              <h3 className="font-bold text-slate-900 text-sm">Threat Severity Distribution</h3>
              <div className="flex justify-center items-center py-4">
                <div className="w-32 h-32 rounded-full border-8 border-red-500 border-t-amber-400 border-l-blue-400 flex flex-col items-center justify-center shadow-inner">
                  <span className="text-3xl font-black text-slate-900">{metrics.severities.CRITICAL}</span>
                  <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Critical</span>
                </div>
              </div>
              <div className="grid grid-cols-4 text-center text-xs pt-3 border-t border-slate-100 font-semibold">
                <div><div className="text-red-600 font-black">{metrics.severities.CRITICAL}</div><div className="text-[10px] text-slate-400">Critical</div></div>
                <div><div className="text-amber-600 font-black">{metrics.severities.HIGH}</div><div className="text-[10px] text-slate-400">High</div></div>
                <div><div className="text-blue-600 font-black">{metrics.severities.MEDIUM}</div><div className="text-[10px] text-slate-400">Medium</div></div>
                <div><div className="text-slate-500 font-black">{metrics.severities.LOW}</div><div className="text-[10px] text-slate-400">Low</div></div>
              </div>
            </div>

            {/* Highest-Risk Devices */}
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between">
              <h3 className="font-bold text-slate-900 text-sm mb-2">Highest-Risk Twin Assets</h3>
              <div className="space-y-2.5">
                {metrics.highestRiskDevices.map((d: any) => (
                  <div key={d.id} className="flex items-center justify-between p-2.5 rounded-lg border border-slate-100 bg-slate-50 hover:bg-white hover:border-blue-200 transition">
                    <div>
                      <Link 
                        href="/network-twin" 
                        onClick={() => setSelectedDeviceId(d.id)}
                        className="font-bold text-xs text-blue-600 hover:underline flex items-center space-x-1"
                      >
                        <span>{d.hostname}</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </Link>
                      <div className="text-[10px] text-slate-400 font-mono font-semibold">{d.id}</div>
                    </div>
                    <div className="text-right">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-black ${d.tier === "CRITICAL" ? "bg-red-100 text-red-700" : "bg-amber-100 text-amber-700"}`}>
                        {d.score}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
              <div className="text-[11px] text-slate-400 pt-2 text-right">Composite Formula: P x C x V x I</div>
            </div>

            {/* Incident Operational Status */}
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between">
              <h3 className="font-bold text-slate-900 text-sm">Incident Triage Posture</h3>
              <div className="space-y-3 my-auto">
                <div className="flex justify-between items-center text-xs">
                  <span className="font-semibold text-slate-600">Open Incidents</span>
                  <span className="font-bold px-2 py-0.5 rounded bg-red-50 text-red-700">{metrics.incidentStatuses.OPEN}</span>
                </div>
                <div className="flex justify-between items-center text-xs">
                  <span className="font-semibold text-slate-600">Active Investigation</span>
                  <span className="font-bold px-2 py-0.5 rounded bg-amber-50 text-amber-700">{metrics.incidentStatuses.INVESTIGATING}</span>
                </div>
                <div className="flex justify-between items-center text-xs">
                  <span className="font-semibold text-slate-600">Resolved Today</span>
                  <span className="font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700">{metrics.incidentStatuses.RESOLVED}</span>
                </div>
                <div className="flex justify-between items-center text-xs">
                  <span className="font-semibold text-slate-600">Archived Closed</span>
                  <span className="font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-600">{metrics.incidentStatuses.CLOSED}</span>
                </div>
              </div>
              <Link href="/incidents" className="text-center text-xs font-bold text-blue-600 hover:underline pt-2 border-t border-slate-100">
                Open SOAR Incident Center ->
              </Link>
            </div>
          </div>

          {/* Chronological Operational Feed */}
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
            <h3 className="font-bold text-slate-900 text-sm mb-3">Live Chronological Activity Stream</h3>
            <div className="space-y-2">
              {metrics.recentFeed.map((item: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between text-xs p-2.5 rounded-lg border border-slate-100 hover:bg-slate-50 transition">
                  <div className="flex items-center space-x-3">
                    <span className="font-mono text-slate-400 font-semibold">{item.time}</span>
                    <span className={`text-[10px] font-black px-1.5 py-0.5 rounded ${
                      item.sev === "CRITICAL" ? "bg-red-100 text-red-700" :
                      item.sev === "HIGH" ? "bg-amber-100 text-amber-700" : "bg-blue-100 text-blue-700"
                    }`}>
                      {item.type}
                    </span>
                    <span className="font-semibold text-slate-800">{item.label}</span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-500 font-bold">{item.target}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}