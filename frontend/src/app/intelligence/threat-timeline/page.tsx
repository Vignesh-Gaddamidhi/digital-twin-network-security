"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Clock, ShieldAlert, Cpu, Flame, Route, ShieldCheck, CheckCircle2, Lock } from "lucide-react";

export default function ThreatTimelinePage() {
  const [filterSource, setFilterSource] = useState<string>("ALL");

  const timelineEvents = [
    { time: "08:10:00.124", stage: "TRAFFIC", source: "SIMULATION", desc: "Baseline normal HTTP GET traffic generated on WEB-01", sev: "INFO", device: "WEB-01" },
    { time: "08:11:15.840", stage: "ANOMALY", source: "ZEEK", desc: "Connection frequency spike detected (1,450 pkts/s)", sev: "MEDIUM", device: "WEB-01" },
    { time: "08:11:45.210", stage: "DETECTION", source: "SURICATA", desc: "ET DOS Slowloris signature triggered (SID: 200142)", sev: "HIGH", device: "WEB-01" },
    { time: "08:12:02.050", stage: "PREDICTION", source: "ML_ENSEMBLE", desc: "Threat Classifier predicts LATERAL_MOVEMENT (Prob: 96.4%)", sev: "CRITICAL", device: "WEB-01" },
    { time: "08:12:18.910", stage: "RISK", source: "RISK_ENGINE", desc: "Composite Risk elevated from 24.0 -> 85.0 (P*C*V*I)", sev: "CRITICAL", device: "WEB-01" },
    { time: "08:13:00.440", stage: "ATTACK_PATH", source: "PATH_ENGINE", desc: "Attack Vector illuminated: CLIENT-01 ➔ WEB-01 ➔ DB-01", sev: "CRITICAL", device: "DB-01" },
    { time: "08:13:20.100", stage: "ALERT", source: "SOC_HUB", desc: "Alert ALT-20260916-001 created & triaged to CRITICAL", sev: "CRITICAL", device: "WEB-01" },
    { time: "08:14:05.620", stage: "RESPONSE", source: "PLAYBOOK", desc: "Playbook ISOLATE_DEVICE simulated on WEB-01", sev: "INFO", device: "WEB-01" },
    { time: "08:15:00.000", stage: "TWIN_MUTATION", source: "TWIN_CORE", desc: "Device state mutated to ISOLATED; incident links severed", sev: "SUCCESS", device: "WEB-01" }
  ];

  const filteredEvents = filterSource === "ALL"
    ? timelineEvents
    : timelineEvents.filter((e) => e.source === filterSource);

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Microsecond Threat Event Timeline" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Chronological Filter Bar */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-slate-400 mr-2">Filter Source:</span>
              {["ALL", "SIMULATION", "ZEEK", "SURICATA", "ML_ENSEMBLE", "RISK_ENGINE", "PLAYBOOK"].map((src) => (
                <button
                  key={src}
                  onClick={() => setFilterSource(src)}
                  className={`text-xs font-bold px-3 py-1.5 rounded-lg transition ${
                    filterSource === src ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                  }`}
                >
                  {src}
                </button>
              ))}
            </div>
            <span className="text-xs font-mono text-slate-500 font-semibold">Microsecond Clock Synchronized</span>
          </div>

          {/* Timeline Stream */}
          <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
            <div className="relative pl-6 border-l-2 border-blue-500 space-y-6 text-xs">
              {filteredEvents.map((e, idx) => (
                <div key={idx} className="relative group">
                  <div className={`absolute -left-[31px] top-0.5 w-3 h-3 rounded-full ring-4 ${
                    e.sev === "CRITICAL" ? "bg-red-600 ring-red-100" :
                    e.sev === "HIGH" ? "bg-amber-500 ring-amber-100" : "bg-blue-600 ring-blue-100"
                  }`} />
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2.5">
                      <span className="font-mono text-slate-400 text-[11px] font-bold">{e.time}</span>
                      <span className={`text-[9px] font-black px-1.5 py-0.5 rounded ${
                        e.sev === "CRITICAL" ? "bg-red-100 text-red-700" :
                        e.sev === "HIGH" ? "bg-amber-100 text-amber-700" : "bg-slate-100 text-slate-600"
                      }`}>
                        {e.stage}
                      </span>
                      <span className="font-bold text-slate-900">{e.desc}</span>
                    </div>
                    <span className="font-mono text-slate-500 font-semibold">Target: {e.device}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}