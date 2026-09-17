"use client";

import React from "react";
import Link from "next/link";
import { useSoc } from "../lib/socContext";
import { Search, AlertTriangle, X, Bell } from "lucide-react";

export default function GlobalModalOverlays() {
  const {
    isCommandPaletteOpen, setIsCommandPaletteOpen,
    searchQuery, setSearchQuery, searchResults,
    isTriageDrawerOpen, setIsTriageDrawerOpen,
    isDbDisconnectedModalOpen, setIsDbDisconnectedModalOpen
  } = useSoc();

  return (
    <>
      {isCommandPaletteOpen && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-md z-50 flex items-start justify-center pt-24">
          <div className="w-[620px] glass-panel-glow rounded-xl overflow-hidden border border-cyber-cyan/40 shadow-2xl animate-in fade-in zoom-in duration-150">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-3 w-full">
                <Search className="w-5 h-5 text-cyber-cyan shrink-0" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Type a device, alert, CVE, or IP..."
                  autoFocus
                  className="w-full bg-transparent border-none text-sm font-mono text-white placeholder-slate-500 focus:outline-none"
                />
              </div>
              <button 
                onClick={() => setIsCommandPaletteOpen(false)}
                className="text-slate-500 hover:text-slate-300 font-mono text-xs"
              >
                ESC
              </button>
            </div>

            <div className="max-h-[380px] overflow-y-auto p-2">
              {searchResults.length === 0 ? (
                <div className="py-12 text-center text-xs font-mono text-slate-500">
                  No matching entities found. Type "WEB-01", "Alert", or "CVE-2026".
                </div>
              ) : (
                <div className="space-y-1">
                  {searchResults.map((item) => (
                    <Link
                      key={item.id}
                      href={item.route}
                      onClick={() => setIsCommandPaletteOpen(false)}
                      className="flex items-center justify-between p-3 rounded-lg hover:bg-slate-800/80 border border-transparent hover:border-slate-700 transition"
                    >
                      <div>
                        <div className="font-mono font-bold text-slate-200 text-xs flex items-center space-x-2">
                          <span>{item.title}</span>
                          <span className="text-[9px] bg-slate-800 text-slate-400 border border-slate-700 px-1.5 py-0.5 rounded uppercase">
                            {item.type}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 mt-0.5">{item.subtitle}</div>
                      </div>
                      {item.severity && (
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                          item.severity === "CRITICAL" ? "bg-cyber-crimson/20 text-cyber-crimson border border-cyber-crimson/40" :
                          item.severity === "HIGH" ? "bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40" :
                          "bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40"
                        }`}>
                          {item.severity}
                        </span>
                      )}
                    </Link>
                  ))}
                </div>
              )}
            </div>

            <div className="px-4 py-2 bg-obsidian-900/90 border-t border-slate-800 flex justify-between items-center text-[10px] font-mono text-slate-500">
              <span>Navigate with [↑][↓]</span>
              <span>Open route [ENTER]</span>
            </div>
          </div>
        </div>
      )}

      {isTriageDrawerOpen && (
        <div className="fixed inset-y-0 right-0 w-96 glass-panel border-l border-slate-800 z-50 shadow-2xl flex flex-col justify-between animate-in slide-in-from-right duration-200">
          <div className="p-5 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center space-x-2 font-mono font-bold text-sm text-white">
              <Bell className="w-4 h-4 text-cyber-cyan" />
              <span>ACTIVE TRIAGE DRAWER</span>
            </div>
            <button onClick={() => setIsTriageDrawerOpen(false)} className="text-slate-400 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex-1 p-4 overflow-y-auto space-y-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-cyber-crimson/10 border border-cyber-crimson/40 space-y-1.5">
              <div className="flex justify-between items-center">
                <span className="text-cyber-crimson font-bold text-[10px]">CRITICAL (12s ago)</span>
                <span className="text-[10px] text-slate-400 font-bold">ALT-001</span>
              </div>
              <div className="font-bold text-slate-200">Slowloris DOS Saturation on WEB-01</div>
              <div className="text-[10px] text-slate-400">1,200 keepalive slots held on port 80</div>
              <div className="flex space-x-2 pt-1">
                <button className="px-2 py-1 rounded bg-cyber-crimson/20 text-cyber-crimson border border-cyber-crimson/50 text-[10px] font-bold">
                  Acknowledge
                </button>
                <Link href="/incidents" className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                  Investigate
                </Link>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-cyber-amber/10 border border-cyber-amber/40 space-y-1.5">
              <div className="flex justify-between items-center">
                <span className="text-cyber-amber font-bold text-[10px]">SYSTEM (45s ago)</span>
                <span className="text-[10px] text-slate-400 font-bold">REDIS</span>
              </div>
              <div className="font-bold text-slate-200">Redis Stream Buffer Threshold 75%</div>
              <div className="text-[10px] text-slate-400">14,250 msg/s ingestion rate</div>
            </div>

            <div className="p-3 rounded-lg bg-cyber-emerald/10 border border-cyber-emerald/40 space-y-1.5">
              <div className="flex justify-between items-center">
                <span className="text-cyber-emerald font-bold text-[10px]">AUDIT (2m ago)</span>
                <span className="text-[10px] text-slate-400 font-bold">GOV</span>
              </div>
              <div className="font-bold text-slate-200">Response ISOLATE_DEVICE Approved</div>
              <div className="text-[10px] text-slate-400">Operator: Sarah Connor (SIMULATION)</div>
            </div>
          </div>

          <div className="p-4 border-t border-slate-800 bg-obsidian-900">
            <Link 
              href="/alerts" 
              onClick={() => setIsTriageDrawerOpen(false)}
              className="block w-full py-2 text-center text-xs font-mono font-bold rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            >
              Open Complete Alert Center
            </Link>
          </div>
        </div>
      )}

      {isDbDisconnectedModalOpen && (
        <div className="fixed inset-0 bg-black/85 backdrop-blur-lg z-50 flex items-center justify-center p-4">
          <div className="w-[500px] glass-panel-glow border-2 border-cyber-crimson rounded-2xl p-6 text-center space-y-4 shadow-crimson-glow">
            <div className="w-16 h-16 rounded-full bg-cyber-crimson/20 border border-cyber-crimson/50 text-cyber-crimson flex items-center justify-center mx-auto">
              <AlertTriangle className="w-8 h-8 animate-pulse" />
            </div>

            <h3 className="text-base font-mono font-black text-white uppercase tracking-wider">
              PRIMARY PERSISTENCE LAYER DISCONNECTED
            </h3>

            <p className="text-xs font-mono text-slate-300 leading-relaxed">
              Connection to PostgreSQL Cluster (Neon AWS us-east-1) timed out after 30s. Failover active. System in read-only degraded mode. No synthetic data will be hallucinated.
            </p>

            <div className="pt-2 flex flex-col space-y-2">
              <button 
                onClick={() => setIsDbDisconnectedModalOpen(false)}
                className="w-full py-2.5 rounded-lg bg-cyber-crimson text-white font-mono font-bold text-xs shadow-crimson-glow hover:bg-cyber-crimson/90 transition"
              >
                Retry Connection Pool / View Diagnostics
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}