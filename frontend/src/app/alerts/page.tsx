"use client";
import React from "react";
import SocSidebar from "../../components/SocSidebar";
import SocHeader from "../../components/SocHeader";

export default function AlertsPage() {
  const alerts = [
    { id: "ALT-20260916-001", type: "SQL_INJECTION_PROBE", source: "CLIENT-01", target: "WEB-01", severity: "CRITICAL", risk: 85.5 },
    { id: "ALT-20260916-002", type: "PORT_SCAN_SWEEP", source: "EXTERNAL-ATTACKER", target: "WEB-01", severity: "HIGH", risk: 68.0 },
    { id: "ALT-20260916-003", type: "UNAUTHORIZED_RPC_PIVOT", source: "WEB-01", target: "DB-01", severity: "CRITICAL", risk: 88.0 },
  ];

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Security Alerts Hub" />
        <div className="flex-1 p-6 overflow-y-auto space-y-4">
          <h3 className="font-bold text-slate-900 text-sm">Active Triaged Alerts (3)</h3>
          {alerts.map((alt) => (
            <div key={alt.id} className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${alt.severity === "CRITICAL" ? "bg-red-100 text-red-700" : "bg-amber-100 text-amber-700"}`}>
                    {alt.severity}
                  </span>
                  <span className="font-bold text-slate-800 text-sm">{alt.type}</span>
                  <span className="text-xs text-slate-400 font-mono font-semibold">[{alt.id}]</span>
                </div>
                <div className="text-xs text-slate-500 mt-1">Source: {alt.source} ➔ Destination: {alt.target}</div>
              </div>
              <div className="text-right">
                <div className="text-xs text-slate-400">Risk Score</div>
                <div className="text-base font-extrabold text-slate-900">{alt.risk}</div>
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}