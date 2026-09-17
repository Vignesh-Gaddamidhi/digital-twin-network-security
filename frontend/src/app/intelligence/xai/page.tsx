"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Sparkles, Info, Sliders } from "lucide-react";

export default function XAIPage() {
  const [packetRate, setPacketRate] = useState(1450);
  const [portEntropy, setPortEntropy] = useState(4.82);
  const [synRatio, setSynRatio] = useState(0.92);

  // Dynamic calculation for simulated hypothetical SHAP adjustments
  const baseValue = 0.120;
  const flowContribution = (packetRate / 1500) * 0.384;
  const entropyContribution = (portEntropy / 5.0) * 0.292;
  const synContribution = synRatio * 0.185;
  const simulatedProb = Math.min(0.999, Math.max(0.01, baseValue + flowContribution + entropyContribution + synContribution - 0.05));

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Explainable AI (TreeSHAP Attribution Studio)" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Executive Summary Card */}
          <div className="glass-panel p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">Forensic Classification</span>
                <h3 className="text-base font-extrabold text-slate-900 flex items-center space-x-2">
                  <span>LATERAL_MOVEMENT</span>
                  <span className="text-xs bg-red-50 border border-red-200 text-red-700 px-2 py-0.5 rounded font-mono font-bold">
                    P = {(simulatedProb * 100).toFixed(1)}%
                  </span>
                </h3>
                <div className="text-xs text-slate-500 font-mono mt-0.5">
                  Target: WEB-01 | Expected Base Rate: {(baseValue * 100).toFixed(1)}%
                </div>
              </div>
              <div className="text-right">
                <span className="text-xs font-bold text-blue-600 bg-blue-50 border border-blue-200 px-3 py-1 rounded-full flex items-center space-x-1.5">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>TreeSHAP Model Explainer</span>
                </span>
              </div>
            </div>

            <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs text-slate-700 space-y-1">
              <div className="font-bold text-slate-900 flex items-center space-x-1.5">
                <Info className="w-3.5 h-3.5 text-blue-600" />
                <span>Human-Readable Forensic Attribution:</span>
              </div>
              <p className="text-slate-600 leading-relaxed pl-5">
                Anomalous packet bursts (+{flowContribution.toFixed(3)}) and destination port diversity (+{entropyContribution.toFixed(3)}) directed toward database cluster 10.0.3.10 drove {(simulatedProb * 100).toFixed(1)}% lateral movement attribution.
              </p>
            </div>
          </div>

          {/* Interactive Hypothetical Sliders & Real-Time Waterfall */}
          <div className="grid grid-cols-3 gap-6">
            {/* Real-time Feature Controls */}
            <div className="glass-panel p-5 space-y-4">
              <div className="flex items-center space-x-2 border-b border-slate-100 pb-2">
                <Sliders className="w-4 h-4 text-blue-600" />
                <h4 className="font-bold text-slate-900 text-xs uppercase font-mono">Hypothetical Feature Sliders</h4>
              </div>

              <div className="space-y-4 text-xs">
                <div>
                  <div className="flex justify-between text-slate-600 font-semibold mb-1">
                    <span>Packet Rate (pps)</span>
                    <span className="font-mono font-bold text-slate-900">{packetRate} pkts/s</span>
                  </div>
                  <input
                    type="range"
                    min="100"
                    max="3000"
                    value={packetRate}
                    onChange={(e) => setPacketRate(parseInt(e.target.value))}
                    className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                  />
                </div>

                <div>
                  <div className="flex justify-between text-slate-600 font-semibold mb-1">
                    <span>Port Diversity Entropy</span>
                    <span className="font-mono font-bold text-slate-900">{portEntropy.toFixed(2)}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="8"
                    step="0.1"
                    value={portEntropy}
                    onChange={(e) => setPortEntropy(parseFloat(e.target.value))}
                    className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                  />
                </div>

                <div>
                  <div className="flex justify-between text-slate-600 font-semibold mb-1">
                    <span>SYN Flag Ratio</span>
                    <span className="font-mono font-bold text-slate-900">{synRatio.toFixed(2)}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.05"
                    value={synRatio}
                    onChange={(e) => setSynRatio(parseFloat(e.target.value))}
                    className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                  />
                </div>
              </div>
            </div>

            {/* TreeSHAP Contribution Waterfall Table */}
            <div className="glass-panel col-span-2 overflow-hidden flex flex-col justify-between">
              <div className="p-4 border-b border-slate-100 font-bold text-slate-900 text-sm">
                SHAP Contribution Vector (Real-Time Attributions)
              </div>
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                  <tr>
                    <th className="py-2.5 px-4">Feature Name</th>
                    <th className="py-2.5 px-4">Observed Metric</th>
                    <th className="py-2.5 px-4">SHAP Contribution</th>
                    <th className="py-2.5 px-4">Amplification Effect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono">
                  <tr className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-sans font-bold text-slate-900">flow_pkts_per_sec</td>
                    <td className="py-3 px-4 text-slate-600">{packetRate} pkts/s</td>
                    <td className="py-3 px-4 font-bold text-red-600">+{flowContribution.toFixed(3)}</td>
                    <td className="py-3 px-4">
                      <div className="w-32 bg-slate-100 rounded-full h-2 overflow-hidden">
                        <div className="bg-red-500 h-full rounded-full" style={{ width: `${Math.min(100, flowContribution * 250)}%` }} />
                      </div>
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-sans font-bold text-slate-900">dst_port_diversity_entropy</td>
                    <td className="py-3 px-4 text-slate-600">{portEntropy.toFixed(2)}</td>
                    <td className="py-3 px-4 font-bold text-red-600">+{entropyContribution.toFixed(3)}</td>
                    <td className="py-3 px-4">
                      <div className="w-32 bg-slate-100 rounded-full h-2 overflow-hidden">
                        <div className="bg-red-500 h-full rounded-full" style={{ width: `${Math.min(100, entropyContribution * 250)}%` }} />
                      </div>
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-sans font-bold text-slate-900">syn_flag_count_ratio</td>
                    <td className="py-3 px-4 text-slate-600">{synRatio.toFixed(2)}</td>
                    <td className="py-3 px-4 font-bold text-red-600">+{synContribution.toFixed(3)}</td>
                    <td className="py-3 px-4">
                      <div className="w-32 bg-slate-100 rounded-full h-2 overflow-hidden">
                        <div className="bg-red-500 h-full rounded-full" style={{ width: `${Math.min(100, synContribution * 250)}%` }} />
                      </div>
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-sans font-bold text-slate-900">protocol_expected_baseline</td>
                    <td className="py-3 px-4 text-slate-600">TCP/80 Valid</td>
                    <td className="py-3 px-4 font-bold text-emerald-600">-0.050</td>
                    <td className="py-3 px-4">
                      <div className="w-32 bg-slate-100 rounded-full h-2 overflow-hidden">
                        <div className="bg-emerald-500 h-full rounded-full" style={{ width: "25%" }} />
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}