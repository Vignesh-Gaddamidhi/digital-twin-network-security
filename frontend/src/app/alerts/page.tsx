"use client";

import React, { useState } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { BellRing, Search, Filter, ShieldAlert, ArrowUpRight } from "lucide-react";

export default function AlertsPage() {
  const { setSelectedAlertId } = useSoc();
  const [filterSev, setFilterSev] = useState("ALL");

  const alerts = [
    { id: "ALT-20260916-001", time: "10:14:22.054", src: "192.168.1.105:48320", dev: "WEB-01", type: "Slowloris Inbound Attempt", conf: "99%", sev: "CRITICAL", status: "INVESTIGATING" },
    { id: "ALT-20260916-002", time: "10:14:24.812", src: "10.0.1.25:52110", dev: "WEB-01", type: "Lateral Movement Probe", conf: "96%", sev: "CRITICAL", status: "NEW" },
    { id: "ALT-20260916-003", time: "10:13:18.400", src: "10.0.1.50:41200", dev: "CLIENT-01", type: "Port Anomaly Sweep", conf: "88%", sev: "HIGH", status: "INVESTIGATING" },
    { id: "ALT-20260916-004", time: "10:11:05.120", src: "10.0.2.99:53120", dev: "WEB-01", type: "DNS Anomaly Tunneling", conf: "74%", sev: "MEDIUM", status: "RESOLVED" },
  ];

  const filtered = filterSev === "ALL" ? alerts : alerts.filter((a) => a.sev === filterSev);

  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200 font-mono">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Enterprise SOC Alert Center" />

        <div className="flex-1 p-6 flex flex-col space-y-4 overflow-hidden">
          {/* Multi-attribute Filter Toolbar */}
          <div className="glass-panel p-4 rounded-xl border border-slate-800 flex justify-between items-center text-xs">
            <div className="flex items-center space-x-2">
              <span className="text-slate-500 font-bold uppercase text-[10px]">Severity Filter:</span>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((s) => (
                <button
                  key={s}
                  onClick={() => setFilterSev(s)}
                  className={`px-2.5 py-1 rounded border text-[10px] font-bold transition ${
                    filterSev === s ? "bg-cyber-cyan text-obsidian border-cyber-cyan shadow-cyan-glow" : "bg-obsidian-900 text-slate-400 border-slate-800"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>

            <div className="text-[11px] text-slate-400">
              Showing <span className="text-cyber-cyan font-bold">{filtered.length}</span> Active Alerts
            </div>
          </div>

          {/* Alert Ledger Table */}
          <div className="flex-1 glass-panel rounded-xl border border-slate-800 overflow-hidden flex flex-col">
            <div className="overflow-x-auto flex-1">
              <table className="w-full text-xs text-left">
                <thead className="text-[10px] text-slate-400 uppercase bg-obsidian-900/90 border-b border-slate-800 sticky top-0">
                  <tr>
                    <th className="py-3 px-4">Alert ID</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Source IP</th>
                    <th className="py-3 px-4">Affected Device</th>
                    <th className="py-3 px-4">Event Type</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filtered.map((a) => (
                    <tr key={a.id} className="hover:bg-obsidian-800/60 transition">
                      <td className="py-3 px-4 font-bold text-white">{a.id}</td>
                      <td className="py-3 px-4 text-slate-400">{a.time}</td>
                      <td className="py-3 px-4 text-slate-300">{a.src}</td>
                      <td className="py-3 px-4 text-cyber-cyan font-bold">{a.dev}</td>
                      <td className="py-3 px-4 text-slate-200">{a.type}</td>
                      <td className="py-3 px-4 text-slate-400">{a.conf}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded font-black text-[10px] border ${
                          a.sev === "CRITICAL" ? "bg-cyber-crimson/20 border-cyber-crimson/40 text-cyber-crimson" : "bg-cyber-amber/20 border-cyber-amber/40 text-cyber-amber"
                        }`}>
                          {a.sev}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded font-bold text-[9px] ${
                          a.status === "NEW" ? "bg-cyber-cyan/20 text-cyber-cyan" :
                          a.status === "INVESTIGATING" ? "bg-cyber-amber/20 text-cyber-amber" :
                          "bg-cyber-emerald/20 text-cyber-emerald"
                        }`}>
                          {a.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link 
                          href="/incidents" 
                          onClick={() => setSelectedAlertId(a.id)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[10px] font-bold"
                        >
                          Escalate
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}