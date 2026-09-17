"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { BrainCircuit, Clock, TrendingUp, Cpu, ShieldCheck, AlertCircle } from "lucide-react";

export default function PredictionsPage() {
  const [horizon, setHorizon] = useState("30s");

  const predictions = [
    {
      id: "PRD-2026-001",
      device: "WEB-01",
      currentProb: 0.88,
      futureProb: 0.96,
      threatClass: "MALICIOUS",
      category: "LATERAL_MOVEMENT",
      confidence: 0.964,
      model: "RandomForest + LSTM Ensemble",
      version: "v2.4.0",
      horizon: "30s",
      leadTime: "18.4s",
      impactStage: "CREDENTIAL_EXTRACTION",
      status: "HIGH_CONFIDENCE_WARNING",
      riskScore: 85.0
    },
    {
      id: "PRD-2026-002",
      device: "DB-01",
      currentProb: 0.42,
      futureProb: 0.84,
      threatClass: "SUSPICIOUS",
      category: "DATA_EXFILTRATION",
      confidence: 0.912,
      model: "GRU Temporal Classifier",
      version: "v2.1.0",
      horizon: "45s",
      leadTime: "32.1s",
      impactStage: "STAGING_TABLES",
      status: "ELEVATED_WATCH",
      riskScore: 78.4
    },
    {
      id: "PRD-2026-003",
      device: "CLIENT-01",
      currentProb: 0.95,
      futureProb: 0.95,
      threatClass: "MALICIOUS",
      category: "PORT_SCAN",
      confidence: 0.985,
      model: "XGBoost Classifier",
      version: "v3.0.1",
      horizon: "15s",
      leadTime: "0.0s",
      impactStage: "RECONNAISSANCE",
      status: "IMMINENT",
      riskScore: 62.0
    }
  ];

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="ML Predictive Threat Forecasting & Early Warnings" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Top Prediction Gauges */}
          <div className="grid grid-cols-4 gap-4">
            <div className="glass-panel p-4">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Active Model</span>
                <Cpu className="w-4 h-4 text-blue-600" />
              </div>
              <div className="text-base font-black text-slate-900 mt-1">RF + LSTM Ensemble</div>
              <div className="text-[10px] text-slate-400 font-mono">v2.4.0 (Calibrated)</div>
            </div>

            <div className="glass-panel p-4">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Prediction Horizon</span>
                <Clock className="w-4 h-4 text-purple-600" />
              </div>
              <div className="text-2xl font-black text-purple-600 mt-1">{horizon}</div>
              <div className="text-[10px] text-slate-400">Sliding temporal window</div>
            </div>

            <div className="glass-panel p-4">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Mean Early Warning Lead</span>
                <TrendingUp className="w-4 h-4 text-emerald-600" />
              </div>
              <div className="text-2xl font-black text-emerald-600 mt-1">18.4s</div>
              <div className="text-[10px] text-emerald-600 font-semibold">Estimated Impact Time</div>
            </div>

            <div className="glass-panel p-4">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Forecast Confidence</span>
                <ShieldCheck className="w-4 h-4 text-blue-600" />
              </div>
              <div className="text-2xl font-black text-blue-600 mt-1">96.4%</div>
              <div className="text-[10px] text-slate-400">Platt scaling calibrated</div>
            </div>
          </div>

          {/* Dual-Horizon Threat Radar Visual Card */}
          <div className="glass-panel p-6 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-100 pb-3">
              <div>
                <h3 className="font-bold text-slate-900 text-sm">Dual-Horizon Threat Probability Radar</h3>
                <p className="text-xs text-slate-400">Real-time comparison between current detection and future trajectory</p>
              </div>
              <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-amber-50 text-amber-700 border border-amber-200 flex items-center space-x-1.5">
                <AlertCircle className="w-3.5 h-3.5" />
                <span>HIGH_CONFIDENCE_WARNING</span>
              </span>
            </div>

            <div className="grid grid-cols-2 gap-6 py-2">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between">
                <span className="text-xs font-bold text-slate-500 uppercase font-mono">Current Attack Probability</span>
                <div className="text-3xl font-black text-slate-900 my-2">88.0% <span className="text-xs text-red-600 font-bold uppercase">(MALICIOUS)</span></div>
                <div className="w-full bg-slate-200 rounded-full h-2 overflow-hidden">
                  <div className="bg-red-500 h-full rounded-full" style={{ width: "88%" }} />
                </div>
              </div>

              <div className="p-4 rounded-xl bg-red-50/50 border border-red-200 flex flex-col justify-between">
                <span className="text-xs font-bold text-red-700 uppercase font-mono">Forecasted Future Spread (+30s)</span>
                <div className="text-3xl font-black text-red-600 my-2">96.0% <span className="text-xs text-red-700 font-bold uppercase">(IMPACT STAGE)</span></div>
                <div className="w-full bg-red-200 rounded-full h-2 overflow-hidden">
                  <div className="bg-red-600 h-full rounded-full" style={{ width: "96%" }} />
                </div>
              </div>
            </div>
          </div>

          {/* Predictions Table */}
          <div className="glass-panel overflow-hidden">
            <div className="p-4 border-b border-slate-100 font-bold text-slate-900 text-sm flex justify-between items-center">
              <span>Active Threat Trajectory Predictions</span>
              <span className="text-xs font-normal text-slate-400 font-mono">P(Current) vs P(Future Horizon)</span>
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Prediction ID</th>
                  <th className="py-3 px-4">Target Device</th>
                  <th className="py-3 px-4">Predicted Category</th>
                  <th className="py-3 px-4">P(Current)</th>
                  <th className="py-3 px-4">P(Future +30s)</th>
                  <th className="py-3 px-4">Lead Time</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {predictions.map((p) => (
                  <tr key={p.id} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-bold text-blue-600">{p.id}</td>
                    <td className="py-3 px-4 font-bold text-slate-800 font-sans">{p.device}</td>
                    <td className="py-3 px-4 font-sans font-semibold text-slate-700">{p.category}</td>
                    <td className="py-3 px-4 text-slate-600">{(p.currentProb * 100).toFixed(1)}%</td>
                    <td className="py-3 px-4 font-bold text-red-600">{(p.futureProb * 100).toFixed(1)}%</td>
                    <td className="py-3 px-4 font-bold text-emerald-600">{p.leadTime}</td>
                    <td className="py-3 px-4 font-bold text-slate-900">{p.riskScore}</td>
                    <td className="py-3 px-4 font-sans">
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200">
                        {p.status}
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