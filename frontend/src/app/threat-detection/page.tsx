"use client";

import React, { useState } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { 
  ShieldAlert, Radio, Search, Filter, ArrowRight, 
  ExternalLink, Download, AlertTriangle, FileCode
} from "lucide-react";

export default function ThreatDetectionPage() {
  const { setSelectedAlertId, setSelectedDeviceId } = useSoc();
  const [sourceFilter, setSourceFilter] = useState<string>("ALL");

  const threatFeeds = [
    {
      id: "THR-2026-001",
      source: "SURICATA",
      type: "ET DOS HTTP Slowloris Inbound",
      severity: "CRITICAL",
      confidence: 0.99,
      timestamp: "10:18:04.212",
      src: "192.168.1.105:48320",
      dst: "10.0.2.99:80 (WEB-01)",
      protocol: "TCP",
      evidence: "HTTP Slowloris Keep-Alive timeout starvation threshold breached",
      alertId: "ALERT-20260916-001"
    },
    {
      id: "THR-2026-002",
      source: "ZEEK",
      type: "Suspicious SSL Cert Validation Failure",
      severity: "HIGH",
      confidence: 0.94,
      timestamp: "10:18:10.144",
      src: "10.0.1.25:52110 (CLIENT-01)",
      dst: "10.0.2.99:443 (WEB-01)",
      protocol: "TLSv1.3",
      evidence: "Self-signed certificate subject CN does not match internal CA",
      alertId: "ALERT-20260916-002"
    },
    {
      id: "THR-2026-003",
      source: "ML_DETECTOR",
      type: "Ensemble LATERAL_MOVEMENT Pivot",
      severity: "CRITICAL",
      confidence: 0.989,
      timestamp: "10:18:15.890",
      src: "10.0.2.99:38190 (WEB-01)",
      dst: "10.0.3.10:3306 (DB-01)",
      protocol: "TCP",
      evidence: "Random Forest + LSTM score: 0.989 | Feature: Unassigned port query burst",
      alertId: "ALERT-20260916-003"
    },
    {
      id: "THR-2026-004",
      source: "SIMULATION",
      type: "SYN Flood Saturation Test Probe",
      severity: "MEDIUM",
      confidence: 1.0,
      timestamp: "10:18:22.001",
      src: "10.0.1.12:44012",
      dst: "10.0.2.99:80 (WEB-01)",
      protocol: "TCP",
      evidence: "Synthetic inject: 1,450 pkts/s stress cycle",
      alertId: "ALERT-20260916-004"
    }
  ];

  const filteredFeeds = sourceFilter === "ALL" 
    ? threatFeeds 
    : threatFeeds.filter((t) => t.source === sourceFilter);

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="AI / ML Threat Detection & Deep Packet Inspection" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* DPI Source Filter Bar */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-slate-400 mr-2" />
              {["ALL", "SURICATA", "ZEEK", "ML_DETECTOR", "SIMULATION"].map((src) => (
                <button
                  key={src}
                  onClick={() => setSourceFilter(src)}
                  className={`text-xs font-bold px-3 py-1.5 rounded-lg transition ${
                    sourceFilter === src ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                  }`}
                >
                  {src}
                </button>
              ))}
            </div>
            <button className="flex items-center space-x-1 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-lg transition">
              <Download className="w-3.5 h-3.5" />
              <span>Download Live PCAP</span>
            </button>
          </div>

          {/* Threat Records Table with Investigation Handoff */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-400 font-bold uppercase text-[10px]">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Source Engine</th>
                  <th className="py-3 px-4">Threat Type</th>
                  <th className="py-3 px-4">Flow Origin -> Target</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4 text-right">Investigation Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredFeeds.map((t) => (
                  <tr key={t.id} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-mono text-slate-400">{t.timestamp}</td>
                    <td className="py-3 px-4 font-bold text-slate-700">{t.source}</td>
                    <td className="py-3 px-4">
                      <div className="font-bold text-slate-900">{t.type}</div>
                      <div className="text-[11px] text-slate-400">{t.evidence}</div>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-600">
                      <div>{t.src} -></div>
                      <div className="font-bold text-blue-600">{t.dst}</div>
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-800">{(t.confidence * 100).toFixed(1)}%</td>
                    <td className="py-3 px-4">
                      <span className={`text-[10px] font-black px-1.5 py-0.5 rounded ${
                        t.severity === "CRITICAL" ? "bg-red-100 text-red-700" :
                        t.severity === "HIGH" ? "bg-amber-100 text-amber-700" : "bg-blue-100 text-blue-700"
                      }`}>
                        {t.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        href="/alerts"
                        onClick={() => {
                          setSelectedAlertId(t.alertId);
                          setSelectedDeviceId("WEB-01");
                        }}
                        className="inline-flex items-center space-x-1 text-xs font-bold text-blue-600 hover:text-blue-800 bg-blue-50 px-2.5 py-1.5 rounded-lg border border-blue-100 transition"
                      >
                        <span>Investigate</span>
                        <ArrowRight className="w-3 h-3" />
                      </Link>
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