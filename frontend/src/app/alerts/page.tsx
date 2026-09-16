"use client";

import React, { useState } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { BellRing, Filter, Search, ArrowRight, ShieldCheck, AlertOctagon, X } from "lucide-react";

export default function AlertsPage() {
  const { selectedDeviceId, setSelectedDeviceId } = useSoc();
  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [filterStatus, setFilterStatus] = useState<string>("ALL");

  const alerts = [
    {
      id: "ALT-20260916-001",
      timestamp: "10:20:14.102",
      severity: "CRITICAL",
      src: "192.168.1.105:48320",
      dst: "10.0.2.99:80",
      protocol: "TCP",
      port: 80,
      eventType: "SQL_INJECTION_PROBE",
      detectionSource: "SURICATA",
      detectionType: "SIGNATURE_MATCH",
      confidence: 0.99,
      riskScore: 85.0,
      riskLevel: "CRITICAL",
      affectedDevice: "WEB-01",
      status: "NEW",
      evidence: "Malicious payload 'UNION SELECT 1, @@version' observed in URI parameters.",
      predictionId: "PRD-2026-001",
      attackPath: "PATH-01"
    },
    {
      id: "ALT-20260916-002",
      timestamp: "10:20:18.450",
      severity: "HIGH",
      src: "10.0.1.25:52110",
      dst: "10.0.2.99:443",
      protocol: "TLS",
      port: 443,
      eventType: "PORT_SCAN_SWEEP",
      detectionSource: "ZEEK",
      detectionType: "FLOW_BEHAVIOR",
      confidence: 0.94,
      riskScore: 68.0,
      riskLevel: "HIGH",
      affectedDevice: "CLIENT-01",
      status: "INVESTIGATING",
      evidence: "High destination port diversity: 12 ports probed in 500ms.",
      predictionId: "PRD-2026-003",
      attackPath: "PATH-02"
    },
    {
      id: "ALT-20260916-003",
      timestamp: "10:20:25.890",
      severity: "CRITICAL",
      src: "10.0.2.99:38190",
      dst: "10.0.3.10:3306",
      protocol: "TCP",
      port: 3306,
      eventType: "UNAUTHORIZED_RPC_PIVOT",
      detectionSource: "ML_DETECTOR",
      detectionType: "ENSEMBLE_INFERENCE",
      confidence: 0.989,
      riskScore: 88.0,
      riskLevel: "CRITICAL",
      affectedDevice: "DB-01",
      status: "ACKNOWLEDGED",
      evidence: "Ensemble Classifier probability: 0.989 (LATERAL_MOVEMENT pivot).",
      predictionId: "PRD-2026-002",
      attackPath: "PATH-01"
    }
  ];

  const filteredAlerts = alerts.filter((a) => {
    const matchSev = filterSeverity === "ALL" || a.severity === filterSeverity;
    const matchSt = filterStatus === "ALL" || a.status === filterStatus;
    return matchSev && matchSt;
  });

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Security Alerts Hub & Triage Queue" />

        <div className="flex-1 flex overflow-hidden">
          {/* Main Table View */}
          <div className="flex-1 p-6 overflow-y-auto space-y-4">
            {/* Filter Bar */}
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-bold text-slate-400 mr-1">Severity:</span>
                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setFilterSeverity(sev)}
                    className={`text-xs font-bold px-2.5 py-1 rounded-lg transition ${
                      filterSeverity === sev ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-bold text-slate-400 mr-1">Status:</span>
                {["ALL", "NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"].map((st) => (
                  <button
                    key={st}
                    onClick={() => setFilterStatus(st)}
                    className={`text-xs font-bold px-2.5 py-1 rounded-lg transition ${
                      filterStatus === st ? "bg-blue-600 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            {/* Alerts Table */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                  <tr>
                    <th className="py-3 px-4">Alert ID</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Event Type</th>
                    <th className="py-3 px-4">Target Device</th>
                    <th className="py-3 px-4">Detection Source</th>
                    <th className="py-3 px-4">Risk</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredAlerts.map((a) => (
                    <tr
                      key={a.id}
                      onClick={() => setSelectedAlert(a)}
                      className={`hover:bg-slate-50/80 transition cursor-pointer ${
                        selectedAlert?.id === a.id ? "bg-blue-50/50" : ""
                      }`}
                    >
                      <td className="py-3 px-4 font-mono font-bold text-blue-600">{a.id}</td>
                      <td className="py-3 px-4 font-mono text-slate-400">{a.timestamp}</td>
                      <td className="py-3 px-4">
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          a.severity === "CRITICAL" ? "bg-red-100 text-red-700" : "bg-amber-100 text-amber-700"
                        }`}>
                          {a.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-bold text-slate-900">{a.eventType}</td>
                      <td className="py-3 px-4 font-mono text-slate-700 font-semibold">{a.affectedDevice}</td>
                      <td className="py-3 px-4 font-mono text-slate-500">{a.detectionSource}</td>
                      <td className="py-3 px-4 font-mono font-bold text-slate-900">{a.riskScore}</td>
                      <td className="py-3 px-4">
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                          {a.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button className="text-xs font-bold text-blue-600 hover:underline">View Detail</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* 8-Stage Alert Detail Drawer */}
          {selectedAlert && (
            <aside className="w-96 bg-white border-l border-slate-200 p-5 shrink-0 flex flex-col justify-between overflow-y-auto">
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                  <div>
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">Alert Inspection</span>
                    <h3 className="text-sm font-extrabold text-slate-900">{selectedAlert.id}</h3>
                  </div>
                  <button onClick={() => setSelectedAlert(null)} className="p-1 hover:bg-slate-100 rounded-md">
                    <X className="w-4 h-4 text-slate-400" />
                  </button>
                </div>

                <div className="space-y-2.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Event Type</span>
                    <span className="font-bold text-slate-900">{selectedAlert.eventType}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Flow Origin ➔ Target</span>
                    <span className="font-mono text-slate-700">{selectedAlert.src} ➔ {selectedAlert.dst}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Confidence</span>
                    <span className="font-bold text-emerald-600">{(selectedAlert.confidence * 100).toFixed(1)}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Composite Risk</span>
                    <span className="font-bold text-red-600">{selectedAlert.riskScore} ({selectedAlert.riskLevel})</span>
                  </div>
                </div>

                <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 text-xs space-y-1">
                  <div className="font-bold text-slate-800">Forensic Evidence:</div>
                  <div className="text-slate-600">{selectedAlert.evidence}</div>
                </div>

                <div className="bg-blue-50/50 p-3 rounded-lg border border-blue-100 text-xs space-y-1 font-mono">
                  <div className="font-bold text-blue-900 font-sans">Investigation Linkage:</div>
                  <div>Prediction : {selectedAlert.predictionId}</div>
                  <div>Attack Path: {selectedAlert.attackPath}</div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-100 space-y-2">
                <Link
                  href="/incidents"
                  className="w-full block text-center py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-lg transition"
                >
                  Escalate to Incident Investigation ➔
                </Link>
              </div>
            </aside>
          )}
        </div>
      </main>
    </div>
  );
}