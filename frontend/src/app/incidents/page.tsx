"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { 
  AlertOctagon, CheckCircle2, ArrowRight, Clock, 
  ShieldAlert, ShieldCheck, Flame, UserCheck, Play 
} from "lucide-react";

export default function IncidentsPage() {
  const { setSelectedDeviceId } = useSoc();
  const [selectedIncidentId, setSelectedIncidentId] = useState("INC-2026-001");

  const incidents = [
    {
      id: "INC-2026-001",
      title: "Critical Lateral Movement: Infiltration from Corp Client to DB Cluster",
      description: "CVE-2026-RCE exploit on WEB-01 followed by unauthorized port 3306 queries toward DB-01.",
      severity: "CRITICAL",
      status: "INVESTIGATING",
      createdAt: "2026-09-16T10:14:00Z",
      updatedAt: "2026-09-16T10:18:30Z",
      affectedDevices: ["CLIENT-01", "WEB-01", "DB-01"],
      relatedAlerts: ["ALT-20260916-001", "ALT-20260916-003"],
      predictions: ["PRD-2026-001", "PRD-2026-002"],
      riskAssessments: [85.0, 78.4],
      attackPaths: ["PATH-01"],
      responses: ["RESP-20260916-000001 (ISOLATE_DEVICE)"],
      assignedOperator: "SOC_SENIOR_ANALYST"
    }
  ];

  const activeInc = incidents.find((i) => i.id === selectedIncidentId) || incidents[0];

  const timelineStages = [
    { stage: "1. Threat", desc: "CVE-2026-RCE Exploit Injected", time: "10:14:02", state: "COMPLETED" },
    { stage: "2. Event", desc: "Suricata ET DOS HTTP Slowloris Event Generated", time: "10:14:05", state: "COMPLETED" },
    { stage: "3. Alert", desc: "Alert ALT-20260916-001 Triaged (Severity: CRITICAL)", time: "10:14:10", state: "COMPLETED" },
    { stage: "4. Prediction", desc: "ML Forecast: LATERAL_MOVEMENT (Prob: 96.4%)", time: "10:14:14", state: "COMPLETED" },
    { stage: "5. XAI", desc: "SHAP: Unassigned port query burst driver identified", time: "10:14:18", state: "COMPLETED" },
    { stage: "6. Risk", desc: "Composite Asset Risk evaluated: 85.0 (CRITICAL)", time: "10:14:22", state: "COMPLETED" },
    { stage: "7. Attack Path", desc: "Vector PATH-01 Illuminated: CLIENT-01 ➔ WEB-01 ➔ DB-01", time: "10:14:25", state: "COMPLETED" },
    { stage: "8. Recommendation", desc: "Recommended: ISOLATE_DEVICE on WEB-01", time: "10:14:28", state: "COMPLETED" },
    { stage: "9. Response", desc: "Simulated ISOLATE_DEVICE executed (Mode: SIMULATION)", time: "10:14:32", state: "COMPLETED" },
    { stage: "10. Twin Update", desc: "Twin Node WEB-01 mutated to ISOLATED; Path severed", time: "10:14:35", state: "COMPLETED" }
  ];

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Correlated Security Incidents & SOAR Workflows" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Incident Overview Card */}
          <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="px-2.5 py-0.5 rounded bg-red-100 text-red-700 font-bold text-xs">
                  {activeInc.severity}
                </span>
                <span className="text-base font-black text-slate-900">{activeInc.id}</span>
                <span className="text-xs text-slate-400 font-mono">Assigned: {activeInc.assignedOperator}</span>
              </div>
              <span className="text-xs font-bold px-3 py-1 rounded-full bg-amber-50 text-amber-700 border border-amber-200">
                STATUS: {activeInc.status}
              </span>
            </div>

            <h2 className="text-sm font-bold text-slate-800">{activeInc.title}</h2>
            <p className="text-xs text-slate-600">{activeInc.description}</p>

            <div className="grid grid-cols-3 gap-4 pt-2">
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-400 block font-semibold">Affected Devices:</span>
                <span className="font-bold text-slate-800 font-mono">{activeInc.affectedDevices.join(", ")}</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-400 block font-semibold">Correlated Alerts:</span>
                <span className="font-bold text-blue-600 font-mono">{activeInc.relatedAlerts.join(", ")}</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-400 block font-semibold">Simulated Responses:</span>
                <span className="font-bold text-emerald-600 font-mono">{activeInc.responses.join(", ")}</span>
              </div>
            </div>
          </div>

          {/* 10-Stage Investigation Story Timeline */}
          <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
            <h3 className="font-bold text-slate-900 text-sm">10-Stage Chronological Investigation Story</h3>
            <div className="relative pl-6 border-l-2 border-blue-500 space-y-4 text-xs">
              {timelineStages.map((t, idx) => (
                <div key={idx} className="relative group">
                  <div className="absolute -left-[31px] top-0.5 w-3 h-3 rounded-full bg-blue-600 ring-4 ring-blue-100" />
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-900">{t.stage}: {t.desc}</span>
                    <span className="font-mono text-slate-400 text-[11px]">{t.time}</span>
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