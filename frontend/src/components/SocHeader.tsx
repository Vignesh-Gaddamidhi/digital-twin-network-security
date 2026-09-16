"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Search, ShieldAlert, Sparkles, Activity, Bell } from "lucide-react";
import { useSoc } from "../lib/socContext";

export default function SocHeader({ pageTitle }: { pageTitle: string }) {
  const { searchQuery, setSearchQuery, searchResults, realtimeStatus } = useSoc();
  const [isFocused, setIsFocused] = useState(false);

  return (
    <header className="h-16 bg-white border-b border-slate-200 px-6 flex items-center justify-between shrink-0 relative z-30">
      <div className="flex items-center space-x-4">
        <h2 className="text-base font-bold text-slate-800 tracking-tight">{pageTitle}</h2>
        <span className="text-[11px] bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded-full font-semibold flex items-center space-x-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>● {realtimeStatus}</span>
        </span>
      </div>

      {/* Global Search Omni-Bar */}
      <div className="relative w-96">
        <div className="relative flex items-center">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onFocus={() => setIsFocused(true)}
            onBlur={() => setTimeout(() => setIsFocused(false), 250)}
            placeholder="Search devices, alerts, CVEs, attack paths, predictions..."
            className="w-full bg-slate-50 border border-slate-200 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition"
          />
        </div>

        {/* Global Search Results Flyout */}
        {isFocused && searchResults.length > 0 && (
          <div className="absolute top-11 left-0 w-full bg-white border border-slate-200 rounded-lg shadow-xl overflow-hidden py-1 max-h-80 overflow-y-auto">
            <div className="text-[10px] font-bold text-slate-400 px-3 py-1 uppercase bg-slate-50 border-b border-slate-100">
              Matched Security Entities ({searchResults.length})
            </div>
            {searchResults.map((item) => (
              <Link
                key={item.id}
                href={item.route}
                className="flex items-center justify-between px-3 py-2 hover:bg-slate-50 border-b border-slate-50 text-xs transition"
              >
                <div>
                  <div className="font-bold text-slate-800 flex items-center space-x-2">
                    <span>{item.title}</span>
                    <span className="text-[9px] bg-slate-100 text-slate-600 px-1.5 py-0.2 rounded font-mono font-bold">
                      {item.type}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">{item.subtitle}</div>
                </div>
                {item.severity && (
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                    item.severity === "CRITICAL" ? "bg-red-100 text-red-700" :
                    item.severity === "HIGH" ? "bg-amber-100 text-amber-700" : "bg-blue-100 text-blue-700"
                  }`}>
                    {item.severity}
                  </span>
                )}
              </Link>
            ))}
          </div>
        )}
      </div>

      <div className="flex items-center space-x-4">
        <div className="text-right">
          <div className="text-xs font-bold text-slate-800">Security Lead</div>
          <div className="text-[10px] text-slate-400">SOC Operator (Level 3)</div>
        </div>
        <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold text-xs shadow-sm">
          SL
        </div>
      </div>
    </header>
  );
}