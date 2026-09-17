"use client";

import React from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Route, ShieldAlert, Terminal, AlertTriangle, ArrowRight } from "lucide-react";

export default function AttackPathsPage() {
  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200 font-mono">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Attack Path Explorer — Multi-Hop Analysis" />

        <div className="flex-1 p-6 flex flex-col space-y-4 overflow-hidden">
          {/* Main Directed Traversal Canvas */}
          <div className="flex-1 glass-panel rounded-xl border border-slate-800 flex overflow-hidden">
            {/* Graph Node Viewport */}
            <div className="flex-1 p-12 flex items-center justify-around relative bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px]">
              {/* Node 1 */}
              <div className="p-4 rounded-xl border border-slate-700 bg-obsidian-900/90 text-center space-y-1">
                <span className="text-[10px] text-slate-400 font-bold block">INITIAL ACCESS</span>
                <div className="text-xs font-bold text-white">CLIENT-01</div>
                <span className="text-[9px] text-slate-500">10.0.1.25</span>
              </div>

              <div className="flex flex-col items-center space-y-1 text-cyber-amber font-bold">
                <span className="text-[10px]">Port Scan &rarr;</span>
                <ArrowRight className="w-6 h-6 animate-pulse" />
              </div>

              {/* Node 2 */}
              <div className="p-4 rounded-xl border border-cyber-crimson bg-obsidian-800/90 text-center space-y-1 shadow-crimson-glow">
                <span className="text-[10px] text-cyber-crimson font-bold block">EXPLOITED PROXY</span>
                <div className="text-xs font-bold text-white">WEB-01 (DMZ)</div>
                <span className="text-[9px] text-slate-400">10.0.2.99</span>
                <div className="text-[8px] px-1.5 py-0.5 rounded bg-cyber-crimson/20 text-cyber-crimson font-black">
                  COMPROMISED
                </div>
              </div>

              <div className="flex flex-col items-center space-y-1 text-cyber-crimson font-bold">
                <span className="text-[10px]">Lateral Pivot &rarr;</span>
                <ArrowRight className="w-6 h-6 animate-pulse" />
              </div>

              {/* Node 3 */}
              <div className="p-4 rounded-xl border border-cyber-crimson/60 bg-obsidian-900/90 text-center space-y-1">
                <span className="text-[10px] text-slate-400 font-bold block">CROWN JEWEL TARGET</span>
                <div className="text-xs font-bold text-white">DB-01 (Internal)</div>
                <span className="text-[9px] text-slate-500">10.0.3.10:3306</span>
                <div className="text-[8px] px-1.5 py-0.5 rounded bg-cyber-amber/20 text-cyber-amber font-black">
                  AT RISK (REACHABLE)
                </div>
              </div>
            </div>

            {/* Sidebar Blast Radius & CVEs */}
            <div className="w-80 border-l border-slate-800 bg-obsidian-900/95 p-5 flex flex-col justify-between">
              <div className="space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-cyber-crimson" />
                    <span>Blast Radius Breakdown</span>
                  </h3>
                  <div className="text-[10px] text-slate-400 mt-1">Multi-Hop Traversal Risk: 78.4</div>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="p-3 rounded-lg border border-cyber-crimson/40 bg-cyber-crimson/10 space-y-1">
                    <span className="text-[10px] text-cyber-crimson font-bold">EXPLOIT ACTIVE</span>
                    <div className="font-bold text-white">CVE-2026-38408</div>
                    <div className="text-[10px] text-slate-400">OpenSSH RCE via PKCS#11 Provider</div>
                  </div>

                  <div className="p-3 rounded-lg border border-slate-800 bg-slate-800/40 space-y-1">
                    <span className="text-[10px] text-slate-400 font-bold">LATERAL VECTOR</span>
                    <div className="font-bold text-slate-200">Port 3306 Probe</div>
                    <div className="text-[10px] text-slate-400">Direct query route from DMZ to Internal</div>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-obsidian-800 text-[10px] text-slate-400">
                Reachability: HIGH &bull; Containment Action Recommended: <span className="text-cyber-cyan font-bold">ISOLATE_DEVICE (WEB-01)</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}