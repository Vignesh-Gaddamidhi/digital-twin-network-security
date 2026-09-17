"use client";

import React, { useState } from "react";
import Link from "next/link";
import { 
  Search, ShieldAlert, Activity, Bell, Radio, Database,
  Sliders, User, AlertTriangle, X, Terminal, ExternalLink
} from "lucide-react";
import { useSoc } from "../lib/socContext";

export default function SocHeader({ pageTitle }: { pageTitle: string }) {
  const { 
    searchQuery, setSearchQuery, searchResults, realtimeStatus,
    setIsCommandPaletteOpen, isTriageDrawerOpen, setIsTriageDrawerOpen,
    setIsDbDisconnectedModalOpen
  } = useSoc();
  const [isFocused, setIsFocused] = useState(false);

  return (
    <header className="flex flex-col shrink-0 bg-obsidian-900 border-b border-slate-800 relative z-30 select-none">
      <div className="h-11 px-6 flex items-center justify-between border-b border-slate-800/80 text-xs">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-pulse"></span>
            <span className="font-mono text-[11px] tracking-wider text-slate-400 uppercase font-semibold">
              LIVE PERFORMANCE
            </span>
          </div>
          <span className="text-slate-600">»</span>
          <div className="flex items-center space-x-2 font-mono text-[11px]">
            <span className="px-2 py-0.5 rounded bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan font-bold">
              [STREAM: {realtimeStatus}]
            </span>
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
              [API: 12ms]
            </span>
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
              [REDIS: 4,120 msg/s]
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => setIsDbDisconnectedModalOpen(true)}
            className="text-[11px] font-mono text-amber-400/80 hover:text-amber-300 flex items-center space-x-1.5 transition"
            title="Check Persistence Connection"
          >
            <Database className="w-3.5 h-3.5 text-amber-400" />
            <span>NEON CLUSTER: ONLINE</span>
          </button>

          <button
            onClick={() => setIsTriageDrawerOpen(!isTriageDrawerOpen)}
            className="relative p-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-700 border border-slate-700 text-slate-300 transition"
          >
            <Bell className="w-4 h-4 text-cyber-cyan" />
            <span className="absolute -top-1 -right-1 w-4 h-4 bg-cyber-crimson text-white text-[9px] font-bold rounded-full flex items-center justify-center shadow-crimson-glow">
              3
            </span>
          </button>

          <div className="flex items-center space-x-2.5 pl-3 border-l border-slate-800">
            <div className="text-right">
              <div className="text-[11px] font-bold text-slate-200 leading-tight">Sarah Connor</div>
              <div className="text-[9px] font-mono text-cyber-cyan font-semibold tracking-wider uppercase">
                SECURITY_LEAD
              </div>
            </div>
            <div className="w-7 h-7 rounded-full bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan flex items-center justify-center font-bold text-xs shadow-cyan-glow">
              SC
            </div>
          </div>
        </div>
      </div>

      <div className="h-14 px-6 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <h2 className="text-base font-extrabold text-white tracking-tight font-mono flex items-center space-x-2">
            <span className="text-cyber-cyan font-bold">#</span>
            <span>{pageTitle}</span>
          </h2>
        </div>

        <div className="relative w-[480px]">
          <div className="relative flex items-center">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onFocus={() => setIsFocused(true)}
              onBlur={() => setTimeout(() => setIsFocused(false), 250)}
              placeholder="Type a device, alert, CVE, or IP... (Press Ctrl+K)"
              className="w-full bg-obsidian-800/90 border border-slate-700/80 rounded-lg pl-9 pr-16 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan transition shadow-inner"
            />
            <div 
              onClick={() => setIsCommandPaletteOpen(true)}
              className="absolute right-2.5 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] font-mono text-slate-400 font-bold cursor-pointer hover:text-white"
            >
              Ctrl+K
            </div>
          </div>

          {isFocused && searchResults.length > 0 && (
            <div className="absolute top-12 left-0 w-full glass-panel border border-slate-700 rounded-lg shadow-2xl overflow-hidden py-1 max-h-80 overflow-y-auto z-50">
              <div className="text-[10px] font-mono font-bold text-slate-400 px-3 py-1.5 uppercase bg-obsidian-900/90 border-b border-slate-800">
                Matched Security Entities ({searchResults.length})
              </div>
              {searchResults.map((item) => (
                <Link
                  key={item.id}
                  href={item.route}
                  className="flex items-center justify-between px-3 py-2.5 hover:bg-slate-800/60 border-b border-slate-800/40 text-xs transition"
                >
                  <div>
                    <div className="font-bold text-slate-200 flex items-center space-x-2 font-mono">
                      <span>{item.title}</span>
                      <span className="text-[9px] bg-slate-800 text-slate-400 border border-slate-700 px-1.5 py-0.2 rounded font-mono font-semibold">
                        {item.type}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5">{item.subtitle}</div>
                  </div>
                  {item.severity && (
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-black ${
                      item.severity === "CRITICAL" ? "bg-cyber-crimson/20 border border-cyber-crimson/40 text-cyber-crimson" :
                      item.severity === "HIGH" ? "bg-cyber-amber/20 border border-cyber-amber/40 text-cyber-amber" :
                      "bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan"
                    }`}>
                      {item.severity}
                    </span>
                  )}
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="h-6 bg-cyber-crimson/10 border-t border-b border-cyber-crimson/30 overflow-hidden flex items-center select-none">
        <div className="bg-cyber-crimson text-white px-3 h-full flex items-center text-[10px] font-mono font-black uppercase tracking-wider shrink-0 z-10">
          THREAT TICKER:
        </div>
        <div className="overflow-hidden w-full relative">
          <div className="animate-marquee whitespace-nowrap text-[11px] font-mono text-cyber-crimson/90 space-x-8">
            <span>[CRITICAL 10:14:22] Suricata SID:200142 ET DOS HTTP Slowloris Flood on Target WEB-01 (10.0.2.99:80)</span>
            <span>•</span>
            <span>[ML PREDICTION] Dual-Horizon Lateral Vector Probability elevated to 96.4% toward Internal DB-01</span>
            <span>•</span>
            <span>[SAFETY ENFORCED] Automated Playbook ISOLATE_DEVICE staged for simulation approval</span>
            <span>•</span>
            <span>[INTELLIGENCE] TreeSHAP feature attribution: anomalous packet bursts (+0.384) confirmed</span>
            <span>•</span>
            <span>[SYSTEM] Redis streaming bus throughput: 14,250 msgs/s with 0ms consumer lag</span>
          </div>
        </div>
      </div>
    </header>
  );
}