"use client";

import React, { useState } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { 
  AlertOctagon, CheckCircle2, ShieldAlert, Cpu, Sparkles, 
  Flame, Route, Lock, ArrowLeft, Terminal, FileText, ChevronRight
} from "lucide-react";

export default function DeepInvestigationPage({ params }: { params: { id: string } }) {
  const [isTreeShapOpen, setIsTreeShapOpen] = useState(false);

  const lineageSteps = [
    { step: 1, time: "10:14:22.045", title: "Ingress NetFlow Packet Arrival", desc: "192.168.1.105 -> 10.0.2.99:80 [TCP/HTTP Slowloris burst]" },
    { step: 2, time: "10:14:22.054", title: "Suricata Signature SID:200142 Match", desc: "ET DOS Slowloris Inbound Attempt triggered" },
    { step: 3, time: "10:14:24.812", title: "Ensemble ML Threat Prediction (96.4%)", desc: "Random Forest + LSTM classified LATERAL_MOVEMENT" },
    { step: 4, time: "10:14:25.104", title: "TreeSHAP Forensic Attribution Calculated", desc: "Positive contributors: packet rate (+0.384), port entropy (+0.292)" },
    { step: 5, time: "10:14:26.120", title: "Quantitative Risk Calculation (P*C*V*I = 78.4)", desc: "Elevated device risk score above threshold (75.0)" },
    { step: 6, time: "10:14:27.004", title: "Attack Path Discovery Verified", desc: "CLIENT-01 -> WEB-01 -> DB-01 vector reachability confirmed" },
    { step: 7, time: "10:14:30.400", title: "Safe Automated Response Simulation", desc: "ISOLATE_DEVICE executed in SIMULATION (ENFORCED) mode" },
    { step: 8, time: "10:14:30.412", title: "Attentive Escalation Status Dispatched", desc: "SOC Lead Sarah Connor notified via WebSockets" },
    { step: 9, time: "10:14:31.002", title: "Ensemble Secondary Verification", desc: "XGBoost model cross-validated lateral attack hypothesis" },
    { step: 10, time: "10:14:31.905", title: "Simulated Commencing Markers Logged", desc: "Simulation session RUN-20260916-001 registered" },
    { step: 11, time: "10:14:32.100", title: "Previous Device Probes Correlated", desc: "Found prior reconnaissance scans from 10.0.1.25" },
    { step: 12, time: "10:14:32.450", title: "Host Memory Dump Analysis", desc: "Simulated PID 4821 hooked into web listener socket" },
    { step: 13, time: "10:14:33.001", title: "Reverse Shell Detection Signature", desc: "TCP socket probe towards 10.0.3.10:3306 blocked" },
    { step: 14, time: "10:14:33.120", title: "Simulated Snort/Zeek Cross-Reference", desc: "Zeek Notice::Weird_Activity confirmed flow anomalies" },
    { step: 15, time: "10:14:34.004", title: "Action Disallow Process Applied", desc: "Real physical interface modification rejected by safety policy" },
    { step: 16, time: "10:14:35.000", title: "Fallback Containment Policy Active", desc: "VLAN quarantine rule applied on virtual topology edge" },
    { step: 17, time: "10:14:36.120", title: "Contained State Confirmed", desc: "WEB-01 status updated to ISOLATED in PostgreSQL ledger" },
  ];

  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200 font-mono">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle={`Forensic Lineage — ${params.id || "INC-2026-0916-001"}`} />

        <div className="flex-1 p-6 flex space-x-6 overflow-hidden">
          {/* Left Metadata & Affected Assets Card */}
          <div className="w-80 glass-panel rounded-xl border border-slate-800 p-5 flex flex-col justify-between shrink-0">
            <div className="space-y-4">
              <Link href="/incidents" className="text-xs text-cyber-cyan hover:underline flex items-center space-x-1">
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Back to Incidents</span>
              </Link>

              <div className="border-b border-slate-800 pb-3">
                <span className="text-[10px] text-cyber-crimson font-bold block">CRITICAL CASE</span>
                <h3 className="text-sm font-bold text-white mt-1">INC-2026-0916-001</h3>
                <div className="text-[11px] text-slate-400 mt-0.5">Lateral Movement Infiltration</div>
              </div>

              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-[10px] text-slate-500 block">ASSIGNED OPERATOR</span>
                  <span className="font-bold text-slate-200">Sarah Connor (Level 3)</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block">AFFECTED ASSETS</span>
                  <span className="font-bold text-cyber-cyan">WEB-01 (10.0.2.99)</span>
                  <span className="block text-slate-400">DB-01 (10.0.3.10)</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block">CONTAINMENT STATUS</span>
                  <span className="px-2 py-0.5 rounded bg-purple-900/40 text-purple-300 border border-purple-700 font-bold text-[10px]">
                    ISOLATED (SIMULATION)
                  </span>
                </div>
              </div>
            </div>

            <button 
              onClick={() => setIsTreeShapOpen(!isTreeShapOpen)}
              className="w-full py-2.5 rounded-lg bg-cyber-cyan/10 hover:bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan text-xs font-bold transition shadow-cyan-glow"
            >
              {isTreeShapOpen ? "Close TreeSHAP Details" : "Inspect TreeSHAP Drivers"}
            </button>
          </div>

          {/* Center 17-Link Chronological Storyboard */}
          <div className="flex-1 glass-panel rounded-xl border border-slate-800 p-6 flex flex-col overflow-hidden">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
              Microsecond Forensic Chronological Lineage (17 of 17 Links Confirmed)
            </h3>

            <div className="flex-1 overflow-y-auto space-y-3 pr-2">
              {lineageSteps.map((s) => (
                <div key={s.step} className="flex items-start space-x-3 p-3 rounded-lg border border-slate-800/80 bg-obsidian-900/60 hover:border-slate-700 transition">
                  <span className="w-6 h-6 rounded-full bg-cyber-cyan/10 border border-cyber-cyan/40 text-cyber-cyan flex items-center justify-center font-bold text-[11px] shrink-0 mt-0.5">
                    {s.step}
                  </span>
                  <div className="flex-1">
                    <div className="flex justify-between items-center text-xs">
                      <span className="font-bold text-slate-200">{s.title}</span>
                      <span className="text-[10px] text-slate-500">{s.time}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">{s.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Slide-out TreeSHAP Details Drawer */}
          {isTreeShapOpen && (
            <div className="w-80 glass-panel rounded-xl border border-cyber-cyan/40 p-5 flex flex-col justify-between shrink-0 shadow-cyan-glow animate-in slide-in-from-right duration-150">
              <div className="space-y-4">
                <div className="border-b border-slate-800 pb-2">
                  <h4 className="text-xs font-bold text-white flex items-center space-x-2">
                    <Sparkles className="w-4 h-4 text-cyber-cyan" />
                    <span>TreeSHAP Local Drivers</span>
                  </h4>
                  <div className="text-[10px] text-slate-400">Attribution for Prediction #0098</div>
                </div>

                <div className="space-y-2 text-xs">
                  <div>
                    <div className="flex justify-between text-[11px]">
                      <span>flow_pkts_per_sec</span>
                      <span className="text-cyber-crimson font-bold">+0.384</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full mt-1">
                      <div className="bg-cyber-crimson h-full rounded-full" style={{ width: "85%" }} />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-[11px]">
                      <span>dst_port_diversity_entropy</span>
                      <span className="text-cyber-crimson font-bold">+0.292</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full mt-1">
                      <div className="bg-cyber-crimson h-full rounded-full" style={{ width: "65%" }} />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-[11px]">
                      <span>syn_flag_ratio</span>
                      <span className="text-cyber-cyan font-bold">-0.050</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full mt-1">
                      <div className="bg-cyber-cyan h-full rounded-full" style={{ width: "15%" }} />
                    </div>
                  </div>
                </div>
              </div>

              <div className="text-[10px] text-slate-500 bg-obsidian-900 p-2.5 rounded border border-slate-800">
                Model: RandomForest+LSTM Ensemble v2.4.0 (Trained on 100k NetFlow records).
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}