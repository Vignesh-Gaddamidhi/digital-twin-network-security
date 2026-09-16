"use client";

import React, { useState } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { Route, ShieldAlert, ArrowRight, ShieldCheck, CheckCircle2, Lock } from "lucide-react";

export default function AttackPathsPage() {
  const { setSelectedDeviceId } = useSoc();
  const [activePathId, setActivePathId] = useState("PATH-01");

  const attackPaths = [
    {
      pathId: "PATH-01",
      source: "EXTERNAL-ATTACKER (WAN)",
      entryDevice: "CLIENT-01 (10.0.1.25)",
      intermediate: "WEB-01 (10.0.2.99)",
      target: "DB-01 (10.0.3.10)",
      riskScore: 84.5,
      reachability: "ACTIVE (SIMULATED)",
      vulnerabilities: ["CVE-2026-RCE", "Weak MySQL Ingress ACL"],
      statusColor: "text-red-600 bg-red-50 border-red-200"
    },
    {
      pathId: "PATH-02",
      source: "COMPROMISED-ENDPOINT (Corp)",
      entryDevice: "CLIENT-02 (10.0.1.26)",
      intermediate: "FILE-SHARE (10.0.1.44)",
      target: "DB-01 (10.0.3.10)",
      riskScore: 68.0,
      reachability: "POSSIBLE",
      vulnerabilities: ["SMB Signing Disabled"],
      statusColor: "text-amber-600 bg-amber-50 border-amber-200"
    },
    {
      pathId: "PATH-03",
      source: "EXTERNAL-PROBE (WAN)",
      entryDevice: "API-GW-01 (10.0.2.15)",
      intermediate: "WEB-01 (10.0.2.99)",
      target: "DB-01 (10.0.3.10)",
      riskScore: 0.0,
      reachability: "BLOCKED",
      vulnerabilities: ["ISOLATE_DEVICE Applied"],
      statusColor: "text-slate-600 bg-slate-100 border-slate-200"
    }
  ];

  const selectedPath = attackPaths.find((p) => p.pathId === activePathId) || attackPaths[0];

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Multi-Hop Attack Path & Blast Radius Graph" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Path Traversal Visual Ribbon */}
          <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">Selected Attack Vector</span>
                <h3 className="text-base font-extrabold text-slate-900">{selectedPath.pathId}</h3>
              </div>
              <span className={`text-xs font-bold px-3 py-1 rounded-full border ${selectedPath.statusColor}`}>
                STATUS: {selectedPath.reachability}
              </span>
            </div>

            {/* Graph Node Traversal Visualization */}
            <div className="flex items-center justify-between bg-slate-50 p-5 rounded-xl border border-slate-200 font-mono text-xs">
              <div className="text-center">
                <div className="w-10 h-10 rounded-full bg-red-600 text-white flex items-center justify-center font-bold mx-auto mb-1 shadow">WAN</div>
                <div className="font-bold text-slate-800 text-[11px]">{selectedPath.source}</div>
              </div>
              <ArrowRight className="w-5 h-5 text-slate-300" />

              <div className="text-center">
                <div className="w-10 h-10 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold mx-auto mb-1 shadow">GW</div>
                <div className="font-bold text-slate-800 text-[11px]">{selectedPath.entryDevice}</div>
              </div>
              <ArrowRight className="w-5 h-5 text-slate-300" />

              <div className="text-center">
                <div className="w-10 h-10 rounded-full bg-amber-500 text-white flex items-center justify-center font-bold mx-auto mb-1 shadow">WEB</div>
                <div className="font-bold text-slate-800 text-[11px]">{selectedPath.intermediate}</div>
              </div>
              <ArrowRight className="w-5 h-5 text-slate-300" />

              <div className="text-center">
                <div className="w-10 h-10 rounded-full bg-purple-600 text-white flex items-center justify-center font-bold mx-auto mb-1 shadow">DB</div>
                <div className="font-bold text-slate-800 text-[11px]">{selectedPath.target}</div>
              </div>
            </div>

            {/* Playbook Mitigation Handoff Button */}
            <div className="flex justify-between items-center pt-2">
              <div className="text-xs text-slate-500">
                Identified Vulnerabilities: <span className="font-bold text-slate-800">{selectedPath.vulnerabilities.join(", ")}</span>
              </div>
              <Link
                href="/incidents"
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-lg transition shadow-sm"
              >
                Mitigate Attack Path via Response Playbook
              </Link>
            </div>
          </div>

          {/* Paths Index Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 font-bold text-slate-900 text-sm">
              Discovered Multi-Hop Vectors (3)
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Vector ID</th>
                  <th className="py-3 px-4">Traversal Sequence</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Reachability</th>
                  <th className="py-3 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {attackPaths.map((p) => (
                  <tr key={p.pathId} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-mono font-bold text-blue-600">{p.pathId}</td>
                    <td className="py-3 px-4 font-mono text-slate-700">
                      {p.entryDevice} ➔ {p.intermediate} ➔ {p.target}
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-900">{p.riskScore}</td>
                    <td className="py-3 px-4">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${p.statusColor}`}>
                        {p.reachability}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setActivePathId(p.pathId)}
                        className="text-xs font-bold text-blue-600 hover:underline"
                      >
                        Inspect Path
                      </button>
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