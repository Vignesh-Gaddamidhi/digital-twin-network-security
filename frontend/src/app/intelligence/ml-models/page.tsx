"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Cpu, CheckCircle2, TrendingUp, Zap, HardDrive, BarChart3 } from "lucide-react";

export default function MLModelsPage() {
  const [selectedModel, setSelectedModel] = useState("Random Forest");

  const models = [
    { name: "Random Forest", type: "Ensemble Classifier", accuracy: 0.9893, precision: 0.9901, recall: 0.9890, f1: 0.9895, rocAuc: 0.9982, latency: "2.1ms", trainTime: "14.2s", size: "48.2 MB", active: true },
    { name: "XGBoost", type: "Gradient Boosted Trees", accuracy: 0.9947, precision: 0.9921, recall: 0.9967, f1: 0.9944, rocAuc: 0.9991, latency: "1.8ms", trainTime: "22.5s", size: "32.1 MB", active: false },
    { name: "SVM (RBF Kernel)", type: "Support Vector Classifier", accuracy: 0.9635, precision: 0.9615, recall: 0.9680, f1: 0.9647, rocAuc: 0.9820, latency: "4.3ms", trainTime: "45.1s", size: "18.4 MB", active: false },
    { name: "Decision Tree", type: "CART Decision Tree", accuracy: 0.9512, precision: 0.9480, recall: 0.9540, f1: 0.9510, rocAuc: 0.9650, latency: "0.8ms", trainTime: "3.2s", size: "4.8 MB", active: false },
    { name: "Logistic Regression", type: "Linear Generalized Model", accuracy: 0.9120, precision: 0.9050, recall: 0.9180, f1: 0.9114, rocAuc: 0.9410, latency: "0.4ms", trainTime: "1.8s", size: "1.2 MB", active: false },
    { name: "LSTM (Stacked)", type: "Recurrent Sequence Model", accuracy: 0.9810, precision: 0.9790, recall: 0.9830, f1: 0.9810, rocAuc: 0.9940, latency: "6.2ms", trainTime: "180.4s", size: "64.5 MB", active: true },
    { name: "GRU Network", type: "Gated Recurrent Model", accuracy: 0.9785, precision: 0.9760, recall: 0.9810, f1: 0.9785, rocAuc: 0.9920, latency: "4.8ms", trainTime: "142.1s", size: "52.0 MB", active: false },
    { name: "Temporal Ensemble", type: "Hybrid RF + LSTM Pipeline", accuracy: 0.9962, precision: 0.9950, recall: 0.9970, f1: 0.9960, rocAuc: 0.9995, latency: "3.4ms", trainTime: "194.6s", size: "112.7 MB", active: true }
  ];

  const current = models.find((m) => m.name === selectedModel) || models[0];

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Supervised & Temporal ML Model Benchmarks" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Active Model Overview Ribbon */}
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Production Model</span>
                <Cpu className="w-4 h-4 text-blue-500" />
              </div>
              <div className="text-base font-black text-slate-900 mt-1">{current.name}</div>
              <div className="text-[10px] text-slate-400 font-mono">{current.type}</div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Accuracy / F1-Score</span>
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
              </div>
              <div className="text-xl font-black text-emerald-600 mt-1">{(current.accuracy * 100).toFixed(2)}% / {current.f1.toFixed(4)}</div>
              <div className="text-[10px] text-slate-400">Validated on CIC-IDS2017 Test Split</div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Inference Latency</span>
                <Zap className="w-4 h-4 text-amber-500" />
              </div>
              <div className="text-xl font-black text-amber-600 mt-1">{current.latency}</div>
              <div className="text-[10px] text-slate-400">P99 single-flow classification</div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex justify-between items-center text-xs font-semibold text-slate-500">
                <span>Model Artifact Size</span>
                <HardDrive className="w-4 h-4 text-purple-500" />
              </div>
              <div className="text-xl font-black text-purple-600 mt-1">{current.size}</div>
              <div className="text-[10px] text-slate-400">Training Duration: {current.trainTime}</div>
            </div>
          </div>

          {/* Model Comparison Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 font-bold text-slate-900 text-sm flex justify-between items-center">
              <span>Supervised & Temporal Model Leaderboard (8 Architectures)</span>
              <span className="text-xs text-slate-400">Dataset: CIC-IDS2017 Normalized Split (80/20)</span>
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Model Architecture</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Accuracy</th>
                  <th className="py-3 px-4">Precision</th>
                  <th className="py-3 px-4">Recall</th>
                  <th className="py-3 px-4">F1-Score</th>
                  <th className="py-3 px-4">ROC-AUC</th>
                  <th className="py-3 px-4">Latency</th>
                  <th className="py-3 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {models.map((m) => (
                  <tr
                    key={m.name}
                    onClick={() => setSelectedModel(m.name)}
                    className={`hover:bg-slate-50/80 transition cursor-pointer ${
                      selectedModel === m.name ? "bg-blue-50/50" : ""
                    }`}
                  >
                    <td className="py-3 px-4 font-bold text-slate-900 font-sans">{m.name}</td>
                    <td className="py-3 px-4 text-slate-500 font-sans text-[11px]">{m.type}</td>
                    <td className="py-3 px-4">{(m.accuracy * 100).toFixed(2)}%</td>
                    <td className="py-3 px-4">{(m.precision * 100).toFixed(2)}%</td>
                    <td className="py-3 px-4">{(m.recall * 100).toFixed(2)}%</td>
                    <td className="py-3 px-4 font-bold text-blue-600">{m.f1.toFixed(4)}</td>
                    <td className="py-3 px-4">{m.rocAuc.toFixed(4)}</td>
                    <td className="py-3 px-4">{m.latency}</td>
                    <td className="py-3 px-4 font-sans">
                      {m.active ? (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-700">
                          Active In Twin
                        </span>
                      ) : (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-500">
                          Evaluated
                        </span>
                      )}
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