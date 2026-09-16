"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Sparkles, ArrowRight, ShieldAlert, Cpu, Info, CheckCircle2 } from "lucide-react";

export default function XAIPage() {
  const [selectedPredictionId, setSelectedPredictionId] = useState("PRD-2026-001");

  const xaiExplanations = {
    predictionId: "PRD-2026-001",
    targetDevice: "WEB-01",
    predictedCategory: "LATERAL_MOVEMENT",
    probability: 0.964,
    baseValue: 0.120,
    explanation: "Observed anomalous connection frequency and port diversity directed toward database cluster 10.0.3.10, triggering high lateral movement attribution.",
    features: [
      { name: "flow_pkts_per_sec", value: "1,450 pkts/s", contribution: 0.384, positive: true },
      { name: "dst_port_diversity_entropy", value: "4.82", contribution: 0.292, positive: true },
      { name: "syn_flag_count_ratio", value: "0.92", contribution: 0.185, positive: true },
      { name: "packet_payload_entropy", value: "7.14 bits/byte", contribution: 0.112, positive: true },
      { name: "protocol_expected_baseline", value: "TCP/80 Valid", contribution: -0.075, positive: false },
      { name: "known_whitelisted_source_ip", value: "False (External)", contribution: -0.054, positive: false }
    ]
  };

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Explainable AI (SHAP Feature Importance)" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Executive XAI Card */}
          <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">Investigated Inference</span>
                <h3 className="text-base font-extrabold text-slate-900 flex items-center space-x-2">
                  <span>{xaiExplanations.predictedCategory}</span>
                  <span className="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded font-mono">
                    P = {(xaiExplanations.probability * 100).toFixed(1)}%
                  </span>
                </h3>
                <div className="text-xs text-slate-500 font-mono mt-0.5">
                  Target: {xaiExplanations.targetDevice} | Base Rate Expectation: {(xaiExplanations.baseValue * 100).toFixed(1)}%
                </div>
              </div>
              <div className="text-right">
                <span className="text-xs font-bold text-blue-600 bg-blue-50 border border-blue-200 px-3 py-1 rounded-full">
                  TreeSHAP Model Explainer
                </span>
              </div>
            </div>

            <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs text-slate-700 space-y-1">
              <div className="font-bold text-slate-900 flex items-center space-x-1.5">
                <Info className="w-3.5 h-3.5 text-blue-600" />
                <span>Human-Readable Forensic Attribution:</span>
              </div>
              <p className="text-slate-600 leading-relaxed pl-5">{xaiExplanations.explanation}</p>
            </div>
          </div>

          {/* Feature Contribution Waterfall */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 font-bold text-slate-900 text-sm">
              SHAP Value Drivers (Positive Amplification vs Negative Dampening)
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Feature Name</th>
                  <th className="py-3 px-4">Observed Metric Value</th>
                  <th className="py-3 px-4">SHAP Contribution (+/-)</th>
                  <th className="py-3 px-4">Impact Vector</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {xaiExplanations.features.map((f, idx) => (
                  <tr key={idx} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-bold text-slate-900 font-sans">{f.name}</td>
                    <td className="py-3 px-4 text-slate-600">{f.value}</td>
                    <td className="py-3 px-4 font-bold">
                      <span className={f.positive ? "text-red-600" : "text-emerald-600"}>
                        {f.positive ? `+${f.contribution.toFixed(3)}` : f.contribution.toFixed(3)}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden flex">
                        {f.positive ? (
                          <div
                            className="bg-red-500 h-2 rounded-full"
                            style={{ width: `${Math.min(100, f.contribution * 200)}%` }}
                          />
                        ) : (
                          <div
                            className="bg-emerald-500 h-2 rounded-full"
                            style={{ width: `${Math.min(100, Math.abs(f.contribution) * 200)}%` }}
                          />
                        )}
                      </div>
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