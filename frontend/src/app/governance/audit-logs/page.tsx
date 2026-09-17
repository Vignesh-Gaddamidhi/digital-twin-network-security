"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Lock } from "lucide-react";

export default function AuditLogsPage() {
  const [filterAction, setFilterAction] = useState("ALL");

  const auditEntries = [
    {
      auditId: "AUD-1D1DEDC1",
      timestamp: "2026-09-16T10:14:32Z",
      operator: "SOC_SENIOR_ANALYST",
      action: "ISOLATE_DEVICE",
      objectType: "DEVICE",
      objectId: "WEB-01",
      reason: "High threat score (85.0) & LATERAL_MOVEMENT prediction",
      previousState: "NORMAL",
      newState: "ISOLATED",
      mode: "SIMULATION",
      result: "SUCCESS"
    },
    {
      auditId: "AUD-3D4F5A6B",
      timestamp: "2026-09-16T10:14:35Z",
      operator: "AUTOMATED_PLAYBOOK",
      action: "BLOCK_CONNECTION",
      objectType: "LINK",
      objectId: "EDGE-CLIENT-WEB",
      reason: "TCP SYN port scan sweep mitigation",
      previousState: "NORMAL",
      newState: "BLOCKED",
      mode: "SIMULATION",
      result: "SUCCESS"
    },
    {
      auditId: "AUD-5E9240C2",
      timestamp: "2026-09-16T10:14:40Z",
      operator: "SOC_LEAD_ANALYST",
      action: "DISABLE_SERVICE",
      objectType: "SERVICE",
      objectId: "WEB-01:HTTP:80",
      reason: "Active CVE-2026-RCE vulnerability listener probe",
      previousState: "RUNNING",
      newState: "DISABLED",
      mode: "SIMULATION",
      result: "SUCCESS"
    },
    {
      auditId: "AUD-8A7B9C0D",
      timestamp: "2026-09-16T10:14:45Z",
      operator: "AUTOMATED_PLAYBOOK",
      action: "QUARANTINE_ENDPOINT",
      objectType: "DEVICE",
      objectId: "CLIENT-01",
      reason: "Credential brute force threshold violation",
      previousState: "NORMAL",
      newState: "QUARANTINED",
      mode: "SIMULATION",
      result: "SUCCESS"
    },
    {
      auditId: "AUD-REAL-REJECTED",
      timestamp: "2026-09-16T10:14:48Z",
      operator: "SOC_LEAD_ANALYST",
      action: "ISOLATE_DEVICE",
      objectType: "DEVICE",
      objectId: "WEB-01",
      reason: "Illegal attempt to modify physical core switch interface",
      previousState: "NORMAL",
      newState: "REJECTED",
      mode: "REAL",
      result: "SAFETY_VIOLATION_REAL_EXECUTION_BLOCKED"
    },
    {
      auditId: "AUD-9F0E1D2C",
      timestamp: "2026-09-16T10:14:50Z",
      operator: "SOC_SENIOR_ANALYST",
      action: "INCREASE_SECURITY_LEVEL",
      objectType: "DEVICE",
      objectId: "DB-01",
      reason: "Elevated threat context in neighboring subnet",
      previousState: "STANDARD",
      newState: "HIGH",
      mode: "SIMULATION",
      result: "SUCCESS"
    }
  ];

  const filtered = filterAction === "ALL"
    ? auditEntries
    : auditEntries.filter((e) => e.action === filterAction);

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Tamper-Evident Response Audit Logs" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Action Filter Bar */}
          <div className="glass-panel p-4 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-slate-400 mr-2">Action Filter:</span>
              {["ALL", "ISOLATE_DEVICE", "BLOCK_CONNECTION", "DISABLE_SERVICE", "QUARANTINE_ENDPOINT", "INCREASE_SECURITY_LEVEL"].map((act) => (
                <button
                  key={act}
                  onClick={() => setFilterAction(act)}
                  className={`text-[11px] font-bold px-2.5 py-1 rounded-lg transition ${
                    filterAction === act ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                  }`}
                >
                  {act}
                </button>
              ))}
            </div>
            <span className="text-xs font-mono text-emerald-600 font-bold flex items-center space-x-1">
              <Lock className="w-3.5 h-3.5" />
              <span>Immutable Ledger Active</span>
            </span>
          </div>

          {/* Audit Logs Table */}
          <div className="glass-panel overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Audit ID</th>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4">Operator</th>
                  <th className="py-3 px-4">Response Action</th>
                  <th className="py-3 px-4">Target Object</th>
                  <th className="py-3 px-4">State Transition</th>
                  <th className="py-3 px-4">Mode</th>
                  <th className="py-3 px-4">Outcome</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {filtered.map((e) => (
                  <tr key={e.auditId} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-bold text-blue-600">{e.auditId}</td>
                    <td className="py-3 px-4 text-slate-400">{e.timestamp}</td>
                    <td className="py-3 px-4 font-sans font-bold text-slate-700">{e.operator}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200">
                        {e.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-900 font-bold font-sans">
                      {e.objectId} <span className="text-slate-400 text-[10px]">({e.objectType})</span>
                    </td>
                    <td className="py-3 px-4 text-slate-600">
                      {e.previousState} &rarr; <span className="font-bold text-red-600">{e.newState}</span>
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                        e.mode === "REAL" ? "bg-red-100 text-red-700 border border-red-200" : "bg-purple-50 text-purple-700"
                      }`}>
                        {e.mode}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                        e.result.includes("BLOCKED") ? "bg-red-100 text-red-700 border border-red-200" : "bg-emerald-100 text-emerald-700"
                      }`}>
                        {e.result}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}