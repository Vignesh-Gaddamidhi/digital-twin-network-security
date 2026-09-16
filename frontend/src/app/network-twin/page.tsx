"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { useSoc } from "@/lib/socContext";
import { 
  Box, Eye, Layers, ShieldCheck, AlertTriangle, Lock, 
  Terminal, ArrowRight, ShieldAlert, Cpu, Network
} from "lucide-react";

export default function NetworkTwinPage() {
  const { selectedDeviceId, setSelectedDeviceId } = useSoc();
  const [viewMode, setViewMode] = useState<"2D" | "3D">("2D");
  const [filterState, setFilterState] = useState<string>("ALL");

  const devices = [
    { id: "WEB-01", hostname: "srv-web-frontend", ip: "10.0.2.99", subnet: "DMZ Subnet (10.0.2.0/24)", status: "COMPROMISED", risk: 85.0, ports: [80, 443, 22] },
    { id: "API-GW-01", hostname: "srv-api-gateway", ip: "10.0.2.15", subnet: "DMZ Subnet (10.0.2.0/24)", status: "NORMAL", risk: 24.5, ports: [8080] },
    { id: "MAIL-01", hostname: "srv-mail-relay", ip: "10.0.2.20", subnet: "DMZ Subnet (10.0.2.0/24)", status: "NORMAL", risk: 18.0, ports: [25, 587] },
    { id: "CLIENT-01", hostname: "client-dev-null", ip: "10.0.1.25", subnet: "Internal Corp (10.0.1.0/24)", status: "SUSPICIOUS", risk: 62.0, ports: [3389] },
    { id: "FILE-SHARE", hostname: "srv-file-share", ip: "10.0.1.44", subnet: "Internal Corp (10.0.1.0/24)", status: "NORMAL", risk: 32.0, ports: [445] },
    { id: "DB-01", hostname: "srv-db-primary", ip: "10.0.3.10", subnet: "DB Tier (10.0.3.0/24)", status: "AT_RISK", risk: 78.4, ports: [3306, 22] },
  ];

  const selectedDevice = devices.find((d) => d.id === selectedDeviceId) || devices[0];

  const filteredDevices = filterState === "ALL" 
    ? devices 
    : devices.filter((d) => d.status === filterState);

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="VPC Network Digital Twin" />

        {/* Action Header & 2D / 3D Switcher */}
        <div className="h-14 bg-white border-b border-slate-200 px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center space-x-2">
            {["ALL", "NORMAL", "SUSPICIOUS", "COMPROMISED", "ISOLATED"].map((st) => (
              <button
                key={st}
                onClick={() => setFilterState(st)}
                className={`text-xs font-bold px-3 py-1.5 rounded-lg transition ${
                  filterState === st ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          <div className="flex items-center space-x-3">
            <div className="bg-slate-100 p-1 rounded-lg flex space-x-1">
              <button
                onClick={() => setViewMode("2D")}
                className={`flex items-center space-x-1 px-3 py-1 text-xs font-bold rounded-md transition ${
                  viewMode === "2D" ? "bg-white text-blue-600 shadow-sm" : "text-slate-600 hover:text-slate-900"
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>2D Topology</span>
              </button>
              <button
                onClick={() => setViewMode("3D")}
                className={`flex items-center space-x-1 px-3 py-1 text-xs font-bold rounded-md transition ${
                  viewMode === "3D" ? "bg-white text-blue-600 shadow-sm" : "text-slate-600 hover:text-slate-900"
                }`}
              >
                <Box className="w-3.5 h-3.5" />
                <span>3D WebGL</span>
              </button>
            </div>
          </div>
        </div>

        {/* Viewport Canvas + Inspection Drawer */}
        <div className="flex-1 flex overflow-hidden">
          {/* Main Visual Canvas */}
          <div className="flex-1 p-6 flex flex-col justify-between overflow-y-auto">
            {viewMode === "2D" ? (
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 flex-1 relative overflow-hidden flex flex-col justify-between">
                <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">
                  Canonical Subnet Enclaves
                </div>

                <div className="grid grid-cols-3 gap-6 my-auto">
                  {/* DMZ Subnet */}
                  <div className="border-2 border-dashed border-blue-200 rounded-xl p-4 bg-blue-50/30">
                    <div className="text-[11px] font-bold text-blue-600 uppercase mb-3">DMZ Subnet (10.0.2.0/24)</div>
                    <div className="space-y-2">
                      {filteredDevices.filter(d => d.subnet.includes("DMZ")).map(d => (
                        <div
                          key={d.id}
                          onClick={() => setSelectedDeviceId(d.id)}
                          className={`p-3 bg-white rounded-lg border text-xs cursor-pointer transition flex items-center justify-between ${
                            selectedDeviceId === d.id ? "border-blue-600 shadow-md ring-2 ring-blue-100" : "border-slate-200 hover:border-slate-300"
                          }`}
                        >
                          <div>
                            <div className="font-bold text-slate-800">{d.hostname}</div>
                            <div className="text-[10px] text-slate-400 font-mono">{d.ip}</div>
                          </div>
                          <span className={`text-[9px] font-black px-1.5 py-0.5 rounded ${
                            d.status === "COMPROMISED" ? "bg-red-100 text-red-700" : "bg-emerald-100 text-emerald-700"
                          }`}>
                            {d.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Internal Corp Subnet */}
                  <div className="border-2 border-dashed border-purple-200 rounded-xl p-4 bg-purple-50/30">
                    <div className="text-[11px] font-bold text-purple-600 uppercase mb-3">Internal Corp (10.0.1.0/24)</div>
                    <div className="space-y-2">
                      {filteredDevices.filter(d => d.subnet.includes("Internal Corp")).map(d => (
                        <div
                          key={d.id}
                          onClick={() => setSelectedDeviceId(d.id)}
                          className={`p-3 bg-white rounded-lg border text-xs cursor-pointer transition flex items-center justify-between ${
                            selectedDeviceId === d.id ? "border-blue-600 shadow-md ring-2 ring-blue-100" : "border-slate-200 hover:border-slate-300"
                          }`}
                        >
                          <div>
                            <div className="font-bold text-slate-800">{d.hostname}</div>
                            <div className="text-[10px] text-slate-400 font-mono">{d.ip}</div>
                          </div>
                          <span className={`text-[9px] font-black px-1.5 py-0.5 rounded ${
                            d.status === "SUSPICIOUS" ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"
                          }`}>
                            {d.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Database Subnet */}
                  <div className="border-2 border-dashed border-emerald-200 rounded-xl p-4 bg-emerald-50/30">
                    <div className="text-[11px] font-bold text-emerald-600 uppercase mb-3">Database Tier (10.0.3.0/24)</div>
                    <div className="space-y-2">
                      {filteredDevices.filter(d => d.subnet.includes("DB Tier")).map(d => (
                        <div
                          key={d.id}
                          onClick={() => setSelectedDeviceId(d.id)}
                          className={`p-3 bg-white rounded-lg border text-xs cursor-pointer transition flex items-center justify-between ${
                            selectedDeviceId === d.id ? "border-blue-600 shadow-md ring-2 ring-blue-100" : "border-slate-200 hover:border-slate-300"
                          }`}
                        >
                          <div>
                            <div className="font-bold text-slate-800">{d.hostname}</div>
                            <div className="text-[10px] text-slate-400 font-mono">{d.ip}</div>
                          </div>
                          <span className={`text-[9px] font-black px-1.5 py-0.5 rounded ${
                            d.status === "AT_RISK" ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"
                          }`}>
                            {d.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400 border-t border-slate-100 pt-2 flex justify-between">
                  <span>Attack Path: CLIENT-01 -> WEB-01 -> DB-01</span>
                  <span>Drag & Zoom Canvas Supported</span>
                </div>
              </div>
            ) : (
              <div className="bg-slate-900 rounded-xl border border-slate-800 flex-1 flex items-center justify-center text-slate-400 font-mono text-xs shadow-inner">
                [Three.js WebGL Scene Canvas Active - 3D Node Mesh Shaders & Particle Splines Running]
              </div>
            )}
          </div>

          {/* Right Inspection Drawer */}
          <aside className="w-80 bg-white border-l border-slate-200 p-5 shrink-0 flex flex-col justify-between overflow-y-auto">
            <div className="space-y-4">
              <div className="border-b border-slate-100 pb-3">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Inspected Asset</span>
                <h3 className="text-base font-extrabold text-slate-900">{selectedDevice.hostname}</h3>
                <span className="text-xs text-slate-500 font-mono">{selectedDevice.ip} ({selectedDevice.id})</span>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Security State</span>
                  <span className="font-bold text-red-600">{selectedDevice.status}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Risk Score</span>
                  <span className="font-bold text-slate-900">{selectedDevice.risk} / 100</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Open Ports</span>
                  <span className="font-mono text-blue-600 font-bold">{selectedDevice.ports.join(", ")}</span>
                </div>
              </div>

              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100 text-xs text-slate-600 space-y-1">
                <div className="font-bold text-slate-800">Blast Radius Impact:</div>
                <div>* Lateral pivot target to db-01.database.internal</div>
                <div>* Ingress rule: TCP Port 80, 443</div>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-100 space-y-2">
              <button className="w-full py-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-lg transition">
                Trigger Defensive Playbook
              </button>
            </div>
          </aside>
        </div>
      </main>
    </div>
  );
}