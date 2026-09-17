"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Save, CheckCircle2 } from "lucide-react";

export default function SettingsPage() {
  const [realtimeInterval, setRealtimeInterval] = useState(100);
  const [defaultTopology, setDefaultTopology] = useState("2D");
  const [simSpeed, setSimSpeed] = useState("1.0x");
  const [horizonSeconds, setHorizonSeconds] = useState(30);
  const [savedNotice, setSavedNotice] = useState(false);

  const handleSave = () => {
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 3000);
  };

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Platform Engine & Gateway Preferences" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {savedNotice && (
            <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-lg text-xs font-semibold flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              <span>Platform engine settings successfully applied.</span>
            </div>
          )}

          <div className="glass-panel p-6 space-y-6">
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-3">
              Operational Real-Time Stream Parameters
            </h3>

            <div className="grid grid-cols-2 gap-6 text-xs">
              <div className="space-y-1.5">
                <label className="font-bold text-slate-700">Realtime WebSocket Refresh Interval</label>
                <select
                  value={realtimeInterval}
                  onChange={(e) => setRealtimeInterval(parseInt(e.target.value))}
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 font-mono"
                >
                  <option value={50}>50ms (Ultra-High Frequency)</option>
                  <option value={100}>100ms (Standard Production)</option>
                  <option value={250}>250ms (Balanced)</option>
                  <option value={500}>500ms (Low Bandwidth)</option>
                </select>
                <span className="text-[10px] text-slate-400">Controls backend delta broadcast cadence to UI clients.</span>
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-slate-700">Default Network Twin Viewport</label>
                <select
                  value={defaultTopology}
                  onChange={(e) => setDefaultTopology(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 font-mono"
                >
                  <option value="2D">2D Subnet Topology Graph</option>
                  <option value="3D">3D WebGL Spatial Node Canvas</option>
                </select>
                <span className="text-[10px] text-slate-400">Primary initial render format on /network-twin route.</span>
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-slate-700">Attack Simulation Clock Speed</label>
                <select
                  value={simSpeed}
                  onChange={(e) => setSimSpeed(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 font-mono"
                >
                  <option value="0.5x">0.5x (Slow Motion Debug)</option>
                  <option value="1.0x">1.0x (Real-Time 1:1)</option>
                  <option value="2.0x">2.0x (Accelerated)</option>
                  <option value="5.0x">5.0x (High-Rate Stress Test)</option>
                </select>
                <span className="text-[10px] text-slate-400">Multiplier for synthetic packet injection intervals.</span>
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-slate-700">Predictive Temporal Horizon</label>
                <select
                  value={horizonSeconds}
                  onChange={(e) => setHorizonSeconds(parseInt(e.target.value))}
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 font-mono"
                >
                  <option value={15}>15 Seconds</option>
                  <option value={30}>30 Seconds (Default)</option>
                  <option value={45}>45 Seconds</option>
                  <option value={60}>60 Seconds</option>
                </select>
                <span className="text-[10px] text-slate-400">Target window for LSTM & GRU trajectory warnings.</span>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-100 flex items-center justify-end space-x-3">
              <button
                onClick={handleSave}
                className="flex items-center space-x-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg transition shadow-sm"
              >
                <Save className="w-3.5 h-3.5" />
                <span>Save Preferences</span>
              </button>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}