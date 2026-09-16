"use client";

import React from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { Flame, ShieldAlert, Cpu, ArrowUpRight, ShieldCheck, Activity } from "lucide-react";

export default function RiskAnalysisPage() {
  const { setSelectedDeviceId } = useSoc();

  const factorData = {
    compositeScore: 78.4,
    threatProbability: 0.98,
    assetCriticality: 1.0,
    vulnerabilityFactor: 0.8,
    attackImpact: 1.0,
    level: "CRITICAL"
  };

  const deviceRisks = [
    { id: "WEB-01", hostname: "web-01.dmz.internal", p: 0.98, c: 1.0, v: 0.8, i: 1.0, total: 78.4, level: "CRITICAL" },
    { id: "DB-01", hostname: "db-01.database.internal", p: 0.85, c: 1.0, v: 0.9, i: 1.0, total: 76.5, level: "CRITICAL" },
    { id: "CLIENT-01", hostname: "client-01.corp.internal", p: 0.65, c: 0.7, v: 0.6, i: 0.8, total: 21.8, level: "MEDIUM" },
    { id: "API-GW-01", hostname: "api-gw-01.dmz.internal", p: 0.40, c: 0.8, v: 0.5, i: 0.7, total: 11.2, level: "LOW" }
  ];

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Dynamic Risk & Threat Exposure Analysis" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Canonical Factor Breakdown Formula Header */}
          <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-900">Canonical Factor Relationship</h3>
                <div className="text-xs text-slate-500 font-mono mt-0.5">
                  Risk = Threat Probability (P) x Asset Criticality (C) x Vulnerability (V) x Attack Impact (I)
                </div>
              </div>
              <div className="text-right">
                <span className="text-xs text-slate-400 font-semibold block">Composite Network Risk</span>
                <span className="text-3xl font-black text-red-600">{factorData.compositeScore}</span>
              </div>
            </div>

            {/* Factor Decomposition Cards */}
            <div className="grid grid-cols-4 gap-4 pt-2">
              <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200">
                <div className="text-[10px] uppercase font-bold text-slate-400">P - Threat Probability</div>
                <div className="text-xl font-extrabold text-blue-600 mt-1">{factorData.threatProbability}</div>
                <div className="text-[10px] text-slate-500">Derived from ML Classifiers</div>
              </div>
              <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200">
                <div className="text-[10px] uppercase font-bold text-slate-400">C - Asset Criticality</div>
                <div className="text-xl font-extrabold text-purple-600 mt-1">{factorData.assetCriticality}</div>
                <div className="text-[10px] text-slate-500">Tier 1 Production Asset</div>
              </div>
              <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200">
                <div className="text-[10px] uppercase font-bold text-slate-400">V - Vulnerability Factor</div>
                <div className="text-xl font-extrabold text-amber-600 mt-1">{factorData.vulnerabilityFactor}</div>
                <div className="text-[10px] text-slate-500">Active CVE exposure detected</div>
              </div>
              <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200">
                <div className="text-[10px] uppercase font-bold text-slate-400">I - Attack Impact</div>
                <div className="text-xl font-extrabold text-red-600 mt-1">{factorData.attackImpact}</div>
                <div className="text-[10px] text-slate-500">Full host compromise blast</div>
              </div>
            </div>
          </div>

          {/* Asset-Level Risk Matrix Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 font-bold text-slate-900 text-sm">
              Twin Asset Exposure Matrix
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Asset ID</th>
                  <th className="py-3 px-4">Hostname</th>
                  <th className="py-3 px-4">Threat Prob (P)</th>
                  <th className="py-3 px-4">Criticality (C)</th>
                  <th className="py-3 px-4">Vuln Factor (V)</th>
                  <th className="py-3 px-4">Impact (I)</th>
                  <th className="py-3 px-4">Total Risk</th>
                  <th className="py-3 px-4">Severity Tier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {deviceRisks.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-bold text-blue-600">{d.id}</td>
                    <td className="py-3 px-4 font-sans font-semibold text-slate-800">{d.hostname}</td>
                    <td className="py-3 px-4">{d.p.toFixed(2)}</td>
                    <td className="py-3 px-4">{d.c.toFixed(2)}</td>
                    <td className="py-3 px-4">{d.v.toFixed(2)}</td>
                    <td className="py-3 px-4">{d.i.toFixed(2)}</td>
                    <td className="py-3 px-4 font-bold text-slate-900">{d.total.toFixed(1)}</td>
                    <td className="py-3 px-4 font-sans">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        d.level === "CRITICAL" ? "bg-red-100 text-red-700" :
                        d.level === "HIGH" ? "bg-amber-100 text-amber-700" : "bg-blue-100 text-blue-700"
                      }`}>
                        {d.level}
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