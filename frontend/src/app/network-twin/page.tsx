"use client";

import React, { useState } from "react";
import Link from "next/link";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { 
  Network, Server, ShieldAlert, Cpu, Activity, 
  ExternalLink, Layers, Eye, RefreshCw, AlertTriangle
} from "lucide-react";

export default function NetworkTwinPage() {
  const { selectedDeviceId, setSelectedDeviceId } = useSoc();
  const [viewMode, setViewMode] = useState<"2D" | "3D">("2D");

  const nodes = [
    { id: "EDGE-FW-01", name: "edge-fw-01.perimeter", type: "FIREWALL", ip: "10.0.1.1", state: "NORMAL", cpu: 32, rx: "45.2 MB/s", tx: "38.1 MB/s" },
    { id: "CORE-RTR-01", name: "core-rtr-01.backbone", type: "ROUTER", ip: "10.0.1.254", state: "NORMAL", cpu: 44, rx: "128.4 MB/s", tx: "120.9 MB/s" },
    { id: "CLIENT-01", name: "client-01.corp.internal", type: "CLIENT", ip: "10.0.1.25", state: "SUSPICIOUS", cpu: 58, rx: "12.4 MB/s", tx: "8.1 MB/s" },
    { id: "WEB-01", name: "web-01.dmz.internal", type: "SERVER", ip: "10.0.2.99", state: "COMPROMISED", cpu: 85, rx: "12.5 MB/s", tx: "4.2 MB/s" },
    { id: "DB-01", name: "db-01.database.internal", type: "SERVER", ip: "10.0.3.10", state: "NORMAL", cpu: 61, rx: "8.2 MB/s", tx: "14.5 MB/s" },
  ];

  const activeNode = nodes.find((n) => n.id === selectedDeviceId) || nodes[3];

  return (
    <div className="flex h-screen w-screen bg-obsidian text-slate-200">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Network Digital Twin — Topology Canvas" />

        <div className="flex-1 p-6 flex flex-col overflow-hidden space-y-4">
          {/* Top Canvas Controls Ribbon */}
          <div className="flex justify-between items-center bg-obsidian-900/90 border border-slate-800 p-3 rounded-xl">
            <div className="flex items-center space-x-3">
              <span className="text-xs font-mono font-bold text-slate-400">PERSPECTIVE:</span>
              <div className="flex rounded-lg bg-slate-900 border border-slate-800 p-0.5">
                <button
                  onClick={() => setViewMode("2D")}
                  className={`px-3 py-1 text-xs font-mono font-bold rounded ${
                    viewMode === "2D" ? "bg-cyber-cyan text-obsidian shadow-cyan-glow" : "text-slate-400 hover:text-white"
                  }`}
                >
                  2D Logical View
                </button>
                <button
                  onClick={() => setViewMode("3D")}
                  className={`px-3 py-1 text-xs font-mono font-bold rounded ${
                    viewMode === "3D" ? "bg-cyber-cyan text-obsidian shadow-cyan-glow" : "text-slate-400 hover:text-white"
                  }`}
                >
                  3D Spatial WebGL
                </button>
              </div>
            </div>

            <div className="flex items-center space-x-3 text-xs font-mono">
              <span className="flex items-center space-x-1.5 text-cyber-emerald">
                <span className="w-2 h-2 rounded-full bg-cyber-emerald animate-pulse"></span>
                <span>STATE SYNC ACTIVE</span>
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">Nodes: 5 Monitored</span>
            </div>
          </div>

          {/* Main Topological Canvas Workspace */}
          <div className="flex-1 relative glass-panel rounded-xl border border-slate-800 overflow-hidden flex">
            {/* 2D Topological Canvas Simulator */}
            <div className="flex-1 relative bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:20px_20px] p-8 flex items-center justify-around">
              {nodes.map((node) => (
                <div
                  key={node.id}
                  onClick={() => setSelectedDeviceId(node.id)}
                  className={`cursor-pointer p-4 rounded-xl border transition-all duration-200 flex flex-col items-center space-y-2 select-none ${
                    selectedDeviceId === node.id 
                      ? "border-cyber-cyan bg-obsidian-800/90 shadow-cyan-glow scale-105" 
                      : "border-slate-800 bg-obsidian-900/80 hover:border-slate-700"
                  }`}
                >
                  <div className="relative">
                    <Server className={`w-8 h-8 ${
                      node.state === "COMPROMISED" ? "text-cyber-crimson animate-pulse" :
                      node.state === "SUSPICIOUS" ? "text-cyber-amber" : "text-cyber-cyan"
                    }`} />
                    {node.state === "COMPROMISED" && (
                      <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-cyber-crimson animate-ping" />
                    )}
                  </div>
                  <div className="text-center font-mono">
                    <div className="font-bold text-xs text-white">{node.id}</div>
                    <div className="text-[10px] text-slate-500">{node.ip}</div>
                  </div>
                  <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                    node.state === "COMPROMISED" ? "bg-cyber-crimson/20 border-cyber-crimson/40 text-cyber-crimson" :
                    node.state === "SUSPICIOUS" ? "bg-cyber-amber/20 border-cyber-amber/40 text-cyber-amber" :
                    "bg-cyber-emerald/20 border-cyber-emerald/40 text-cyber-emerald"
                  }`}>
                    {node.state}
                  </span>
                </div>
              ))}
            </div>

            {/* Floating Device Inspection Drawer */}
            <div className="w-80 border-l border-slate-800 bg-obsidian-900/95 p-5 flex flex-col justify-between font-mono">
              <div className="space-y-4">
                <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                  <h3 className="font-bold text-sm text-white flex items-center space-x-2">
                    <Cpu className="w-4 h-4 text-cyber-cyan" />
                    <span>Device Telemetry</span>
                  </h3>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    activeNode.state === "COMPROMISED" ? "bg-cyber-crimson/20 text-cyber-crimson" : "bg-cyber-cyan/20 text-cyber-cyan"
                  }`}>
                    {activeNode.id}
                  </span>
                </div>

                <div className="space-y-2.5 text-xs">
                  <div>
                    <span className="text-[10px] text-slate-500 block">HOSTNAME</span>
                    <span className="font-bold text-slate-200">{activeNode.name}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block">PRIMARY IP / INTERFACE</span>
                    <span className="text-slate-300">{activeNode.ip} (eth0)</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block">CPU UTILIZATION</span>
                    <div className="flex items-center space-x-2 mt-1">
                      <div className="flex-1 bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${activeNode.cpu > 80 ? "bg-cyber-crimson" : "bg-cyber-cyan"}`} 
                          style={{ width: `${activeNode.cpu}%` }}
                        />
                      </div>
                      <span className="text-xs font-bold text-slate-200">{activeNode.cpu}%</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2 pt-2">
                    <div className="p-2 rounded bg-slate-800/40 border border-slate-800">
                      <span className="text-[9px] text-slate-500 block">RX LOAD</span>
                      <span className="text-xs text-cyber-cyan font-bold">{activeNode.rx}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-800/40 border border-slate-800">
                      <span className="text-[9px] text-slate-500 block">TX LOAD</span>
                      <span className="text-xs text-slate-300 font-bold">{activeNode.tx}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="border-t border-slate-800 pt-3 space-y-2">
                <div className="text-[11px] text-slate-400 flex justify-between">
                  <span>Attack Path:</span>
                  <span className="text-cyber-crimson font-bold">CLIENT-01 &rarr; WEB-01 &rarr; DB-01</span>
                </div>
                <div className="text-[10px] text-slate-500 text-right">Drag &amp; Zoom Canvas Supported</div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}