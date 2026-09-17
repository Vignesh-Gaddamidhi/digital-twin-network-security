"use client";

import React, { useState } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { 
  ShieldAlert, Radio, Search, Play, Pause, 
  Terminal, ArrowUpRight, Activity, Filter
} from "lucide-react";

export default function ThreatDetectionPage() {
  const { setSelectedAlertId } = useSoc();
  const [isStreaming, setIsStreaming] = useState(true);
  const [filterQuery, setFilterQuery] = useState("");

  const rawPackets = [
    { time: "10:14:22.045", proto: "TCP", src: "192.168.1.105:48320", dst: "10.0.2.99:80", payload: "HTTP [GET] /index.php?id=1' UNION SELECT 1, @@version --" },
    { time: "10:14:22.048", proto: "HTTP", src: "192.168.1.105:48321", dst: "10.0.2.99:80", payload: "HTTP [POST] /login.php [Content-Length: 42800] Keep-Alive" },
    { time: "10:14:22.052", proto: "TCP", src: "192.168.1.105:48322", dst: "10.0.2.99:80", payload: "TCP [SYN] Win=65535 MSS=1460 SACK_PERM TSval=9821034" },
    { time: "10:14:22.055", proto: "DNS", src: "10.0.2.99:53120", dst: "1.1.1.1:53", payload: "DNS Query: stage2-payload-exfil.attacker.internal IN A" },
    { time: "10:14:22.058", proto: "TCP", src: "10.0.2.99:49210", dst: "10.0.3.10:3306", payload: "TCP [SYN] Probe toward MySQL Master port 3306" },
  ];

  const signatures = [
    { time: "10:14:22.054", sensor: "SURICATA", sid: 200142, name: "ET DOS Slowloris Inbound Attempt", sev: "CRITICAL", match: "Observed starved HTTP connection pool" },
    { time: "10:14:22.056", sensor: "ZEEK", sid: 104421, name: "Notice::Weird_Activity", sev: "HIGH", match: "High connection count from single foreign subnet" },
    { time: "10:14:22.059", sensor: "ML_ENGINE", sid: 300101, name: "Ensemble LATERAL_MOVEMENT Hit", sev: "CRITICAL", match: "Port entropy spike 4.82 (96.4% confidence)" },
    { time: "10:14:22.062", sensor: "SURICATA", sid: 200982, name: "ET SCAN Potential MySQL Scanner", sev: "HIGH", match: "Lateral scan from DMZ to Internal Database Tier" },
  ];

  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Threat Detection & Deep Packet Inspection" />

        <div className="flex-1 p-6 flex flex-col overflow-hidden space-y-4 font-mono">
          {/* Top Inspection Control Bar */}
          <div className="glass-panel p-4 rounded-xl border border-slate-800 flex justify-between items-center shrink-0">
            <div className="flex items-center space-x-3 w-96">
              <Search className="w-4 h-4 text-slate-500 shrink-0" />
              <input
                type="text"
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                placeholder="Search raw regex / signature matches..."
                className="w-full bg-obsidian-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-cyan transition"
              />
            </div>

            <div className="flex items-center space-x-4">
              <span className="text-xs text-slate-400 flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-cyber-emerald animate-pulse"></span>
                <span>PCAP BUFFER: ACTIVE</span>
              </span>

              <button
                onClick={() => setIsStreaming(!isStreaming)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-bold border transition ${
                  isStreaming
                    ? "bg-cyber-emerald/20 text-cyber-emerald border-cyber-emerald/40 shadow-emerald-glow"
                    : "bg-slate-800 text-slate-400 border-slate-700"
                }`}
              >
                {isStreaming ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                <span>{isStreaming ? "STREAMING (LIVE)" : "PAUSED"}</span>
              </button>
            </div>
          </div>

          {/* Split View: Left Raw Flows | Right Signatures */}
          <div className="flex-1 grid grid-cols-2 gap-4 overflow-hidden">
            {/* Left: Raw Flow Inspector */}
            <div className="glass-panel rounded-xl border border-slate-800 flex flex-col overflow-hidden">
              <div className="p-3 border-b border-slate-800 bg-obsidian-900/90 flex justify-between items-center">
                <h3 className="text-xs font-bold text-slate-200 flex items-center space-x-2">
                  <Terminal className="w-3.5 h-3.5 text-cyber-cyan" />
                  <span>Incoming Raw Packet Flow Stream</span>
                </h3>
                <span className="text-[10px] text-slate-400">Layer 4/7 Payloads</span>
              </div>
              <div className="flex-1 p-3 overflow-y-auto space-y-2 text-xs">
                {rawPackets.map((pkt, i) => (
                  <div key={i} className="p-2.5 rounded-lg border border-slate-800/80 bg-obsidian-900/60 space-y-1">
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-slate-500">{pkt.time}</span>
                      <span className="px-1.5 py-0.2 rounded font-bold bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan">
                        {pkt.proto}
                      </span>
                    </div>
                    <div className="text-slate-300 font-semibold text-[11px]">
                      {pkt.src} &rarr; {pkt.dst}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate bg-slate-950/80 p-1.5 rounded border border-slate-800/50">
                      {pkt.payload}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: Suricata & Zeek Signatures */}
            <div className="glass-panel rounded-xl border border-slate-800 flex flex-col overflow-hidden">
              <div className="p-3 border-b border-slate-800 bg-obsidian-900/90 flex justify-between items-center">
                <h3 className="text-xs font-bold text-slate-200 flex items-center space-x-2">
                  <ShieldAlert className="w-3.5 h-3.5 text-cyber-crimson" />
                  <span>Suricata / Zeek / ML Signature Engine</span>
                </h3>
                <span className="text-[10px] text-cyber-crimson font-bold">4 Matches Logged</span>
              </div>
              <div className="flex-1 p-3 overflow-y-auto space-y-2 text-xs">
                {signatures.map((sig, i) => (
                  <div key={i} className="p-3 rounded-lg border border-slate-800/80 bg-obsidian-900/60 space-y-1.5">
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-slate-500">{sig.time}</span>
                      <span className="font-bold text-cyber-cyan">{sig.sensor}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-slate-200 text-xs">{sig.name}</span>
                      <span className={`text-[9px] px-1.5 py-0.5 rounded font-black border ${
                        sig.sev === "CRITICAL" ? "bg-cyber-crimson/20 border-cyber-crimson/40 text-cyber-crimson" : "bg-cyber-amber/20 border-cyber-amber/40 text-cyber-amber"
                      }`}>
                        {sig.sev}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-400">SID: {sig.sid} • {sig.match}</div>
                    <div className="pt-1 flex justify-end">
                      <Link 
                        href="/alerts" 
                        onClick={() => setSelectedAlertId("ALT-20260916-001")}
                        className="text-[10px] text-cyber-cyan hover:underline flex items-center space-x-1"
                      >
                        <span>Escalate to SOC Triage</span>
                        <span>&rarr;</span>
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}