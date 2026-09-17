"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { LineChart, Activity, Radio, ArrowUpDown, Server, HardDrive } from "lucide-react";

export default function TrafficAnalyticsPage() {
  const [timeFilter, setTimeFilter] = useState("15m");

  const trafficMetrics = {
    totalPackets: "1,420,850",
    totalBytes: "892.4 MB",
    packetRate: "1,240 pkts/s",
    byteRate: "7.8 MB/s",
    activeConnections: 42,
    protocols: [
      { name: "TCP", pct: 68.4, bytes: "610.4 MB", anomaly: "Elevated SYN ratio" },
      { name: "UDP", pct: 18.2, bytes: "162.4 MB", anomaly: "Normal DNS traffic" },
      { name: "HTTP", pct: 8.5, bytes: "75.8 MB", anomaly: "Slowloris keep-alive burst" },
      { name: "HTTPS", pct: 3.2, bytes: "28.5 MB", anomaly: "Normal TLS handshake" },
      { name: "SSH", pct: 1.1, bytes: "9.8 MB", anomaly: "Brute force password attempts" },
      { name: "ICMP", pct: 0.6, bytes: "5.5 MB", anomaly: "Echo ping sweep" }
    ]
  };

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Real-Time Traffic & NetFlow Analytics" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Time Filter Toolbar */}
          <div className="glass-panel p-4 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-slate-400 mr-2">Time Window:</span>
              {["5m", "15m", "30m", "1h", "6h", "24h"].map((t) => (
                <button
                  key={t}
                  onClick={() => setTimeFilter(t)}
                  className={`text-xs font-bold px-3 py-1.5 rounded-lg transition ${
                    timeFilter === t ? "bg-blue-600 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
            <span className="text-xs font-mono text-emerald-600 font-bold">● NetFlow v9 Ingestion Live</span>
          </div>

          {/* Traffic Gauges */}
          <div className="grid grid-cols-4 gap-4">
            <div className="glass-panel p-4">
              <div className="text-xs font-semibold text-slate-500">Packet Throughput</div>
              <div className="text-2xl font-black text-blue-600 mt-1">{trafficMetrics.packetRate}</div>
              <div className="text-[10px] text-slate-400">Total: {trafficMetrics.totalPackets}</div>
            </div>
            <div className="glass-panel p-4">
              <div className="text-xs font-semibold text-slate-500">Bandwidth Bitrate</div>
              <div className="text-2xl font-black text-emerald-600 mt-1">{trafficMetrics.byteRate}</div>
              <div className="text-[10px] text-slate-400">Total: {trafficMetrics.totalBytes}</div>
            </div>
            <div className="glass-panel p-4">
              <div className="text-xs font-semibold text-slate-500">Active State Connections</div>
              <div className="text-2xl font-black text-purple-600 mt-1">{trafficMetrics.activeConnections}</div>
              <div className="text-[10px] text-slate-400">TCP Handshakes: 34 ESTABLISHED</div>
            </div>
            <div className="glass-panel p-4">
              <div className="text-xs font-semibold text-slate-500">Dominant Protocol</div>
              <div className="text-2xl font-black text-slate-900 mt-1">TCP (68.4%)</div>
              <div className="text-[10px] text-red-600 font-semibold">Anomalous SYN Flood active</div>
            </div>
          </div>

          {/* Protocol Distribution Table */}
          <div className="glass-panel overflow-hidden">
            <div className="p-4 border-b border-slate-100 font-bold text-slate-900 text-sm">
              Protocol Distribution & Behavioral Anomaly Context
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Traffic Share (%)</th>
                  <th className="py-3 px-4">Volume</th>
                  <th className="py-3 px-4">Observed Behavioral Anomaly</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {trafficMetrics.protocols.map((p) => (
                  <tr key={p.name} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-bold text-blue-600 font-sans">{p.name}</td>
                    <td className="py-3 px-4 font-bold">{p.pct}%</td>
                    <td className="py-3 px-4 text-slate-600">{p.bytes}</td>
                    <td className="py-3 px-4 font-sans text-slate-700">
                      <span className={p.anomaly.includes("Slowloris") || p.anomaly.includes("SYN") || p.anomaly.includes("Brute") ? "text-red-600 font-bold" : ""}>
                        {p.anomaly}
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