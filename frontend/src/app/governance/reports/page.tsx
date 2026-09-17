"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Download, FileText, CheckCircle2 } from "lucide-react";

export default function ReportsPage() {
  const [selectedReportType, setSelectedReportType] = useState("Security Summary");
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  const reportCategories = [
    { id: "SEC-SUMMARY", name: "Security Summary", desc: "Executive posture rollup across active threats, health, and open tickets.", records: 240 },
    { id: "THREAT-INTEL", name: "Threat Report", desc: "Deep packet inspection summaries from Suricata, Zeek, and signature detections.", records: 114 },
    { id: "RISK-EXPOSURE", name: "Risk Report", desc: "P x C x V x I exposure calculations and critical asset exposure rankings.", records: 48 },
    { id: "INCIDENT-MGMT", name: "Incident Report", desc: "Aggregated incident tickets, mean-time-to-detect (MTTD), and containment metrics.", records: 18 },
    { id: "ATTACK-PATHS", name: "Attack Path Report", desc: "Multi-hop blast radius vectors, graph reachability, and severed edge states.", records: 12 },
    { id: "SIMULATION-RUNS", name: "Simulation Report", desc: "Synthetic scenario execution audit across all 13 attack archetypes.", records: 156 },
    { id: "ML-EVAL", name: "ML Evaluation Report", desc: "Cross-model benchmark matrix (Accuracy, Precision, Recall, F1, ROC-AUC).", records: 8 },
    { id: "AUDIT-TRAIL", name: "Audit Report", desc: "Tamper-evident forensic ledger capturing operator actions and Twin state transitions.", records: 156 }
  ];

  const handleExport = (format: string) => {
    setExportNotice(`Generated ${selectedReportType} in ${format} format.`);
    setTimeout(() => setExportNotice(null), 3500);
  };

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Executive Security Posture & Compliance Reports" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Header Action Bar */}
          <div className="glass-panel p-4 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <span className="text-xs font-bold text-slate-400">Environment:</span>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                PROD-DIGITAL-TWIN-VPC
              </span>
              <span className="text-xs text-slate-300">|</span>
              <span className="text-xs font-bold text-slate-400">Default Range:</span>
              <span className="text-xs font-semibold text-slate-700">Last 24 Hours</span>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => handleExport("JSON")}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-lg transition"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>
              <button
                onClick={() => handleExport("PDF")}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg transition"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Generate PDF Report</span>
              </button>
            </div>
          </div>

          {exportNotice && (
            <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-lg text-xs font-semibold flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              <span>{exportNotice}</span>
            </div>
          )}

          {/* Report Categories Grid */}
          <div className="grid grid-cols-2 gap-4">
            {reportCategories.map((rep) => (
              <div
                key={rep.id}
                onClick={() => setSelectedReportType(rep.name)}
                className={`p-4 rounded-xl border cursor-pointer transition flex flex-col justify-between ${
                  selectedReportType === rep.name
                    ? "bg-white border-blue-600 shadow-sm ring-2 ring-blue-100"
                    : "bg-white border-slate-200 hover:border-slate-300"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-slate-900 text-sm">{rep.name}</span>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-600">
                      {rep.id}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500">{rep.desc}</p>
                </div>
                <div className="pt-3 mt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
                  <span>Available Records: {rep.records}</span>
                  <span className="text-blue-600 font-bold hover:underline">Select Archetype &rarr;</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}