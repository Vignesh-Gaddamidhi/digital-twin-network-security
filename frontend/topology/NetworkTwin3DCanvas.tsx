"use client";

import React, { useState } from "react";
import { Box, Layers, RotateCw, ZoomIn, ZoomOut, Eye, ShieldAlert } from "lucide-react";

export default function NetworkTwin3DCanvas({ activeDevice }: { activeDevice?: string }) {
  const [zoom, setZoom] = useState(1.0);

  return (
    <div className="relative w-full h-full bg-slate-950 flex items-center justify-center overflow-hidden select-none">
      {/* 3D WebGL Perspective Simulated Canvas */}
      <div 
        className="relative w-full h-full flex items-center justify-center transition-transform duration-300"
        style={{ transform: `scale(${zoom})` }}
      >
        {/* Isometric Grid Plane */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] [background-size:36px_36px] opacity-80" />

        {/* Holographic Perimeter Firewall Plane */}
        <div className="absolute top-24 left-1/4 right-1/4 h-8 bg-amber-500/10 border-2 border-amber-500/40 rounded-lg flex items-center justify-center text-[10px] font-mono font-black text-amber-400 tracking-widest uppercase shadow-amber-glow">
          PERIMETER FIREWALL PLANE
        </div>

        {/* Laser Beam Conduits Connecting 3D Servers */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <line x1="50%" y1="35%" x2="35%" y2="65%" stroke="#00F0FF" strokeWidth="2" strokeDasharray="6 4" className="animate-pulse" />
          <line x1="50%" y1="35%" x2="65%" y2="65%" stroke="#FF003C" strokeWidth="2.5" className="animate-pulse" />
        </svg>

        {/* 3D Server Model: CORE-RTR-01 */}
        <div className="absolute top-[30%] left-1/2 -translate-x-1/2 flex flex-col items-center">
          <div className="w-16 h-16 rounded-xl bg-obsidian-800 border-2 border-cyber-cyan shadow-cyan-glow flex items-center justify-center">
            <Box className="w-8 h-8 text-cyber-cyan" />
          </div>
          <span className="mt-1 font-mono text-[10px] text-white font-bold bg-obsidian-900/90 px-2 py-0.5 rounded border border-slate-800">
            CORE-RTR-01
          </span>
        </div>

        {/* 3D Server Model: DB-01 (Internal) */}
        <div className="absolute top-[60%] left-[32%] flex flex-col items-center">
          <div className="w-20 h-24 rounded-xl bg-obsidian-800 border border-slate-700 shadow-xl flex items-center justify-center">
            <div className="space-y-1 w-full px-2">
              <div className="h-2 bg-slate-700 rounded" />
              <div className="h-2 bg-slate-700 rounded" />
              <div className="h-2 bg-cyber-emerald rounded" />
            </div>
          </div>
          <span className="mt-1 font-mono text-[10px] text-white font-bold bg-obsidian-900/90 px-2 py-0.5 rounded border border-slate-800">
            DB-01 (Internal)
          </span>
        </div>

        {/* 3D Server Model: WEB-01 Enveloped in Wireframe Blast Radius Sphere */}
        <div className="absolute top-[55%] left-[62%] flex flex-col items-center">
          {/* Wireframe Blast Radius Sphere */}
          <div className="relative w-36 h-36 rounded-full border-2 border-dashed border-cyber-crimson bg-cyber-crimson/10 flex items-center justify-center animate-pulse shadow-crimson-glow">
            <div className="w-20 h-24 rounded-xl bg-obsidian-800 border-2 border-cyber-crimson shadow-crimson-glow flex items-center justify-center">
              <div className="space-y-1 w-full px-2">
                <div className="h-2 bg-cyber-crimson rounded" />
                <div className="h-2 bg-cyber-crimson rounded" />
                <div className="h-2 bg-cyber-crimson rounded" />
              </div>
            </div>
            <span className="absolute -bottom-6 text-[9px] font-mono font-bold text-cyber-crimson bg-obsidian-900 px-2 py-0.5 rounded border border-cyber-crimson">
              COMPROMISED BLAST RADIUS
            </span>
          </div>
          <span className="mt-7 font-mono text-[10px] text-white font-bold bg-obsidian-900/90 px-2 py-0.5 rounded border border-slate-800">
            WEB-01 (DMZ)
          </span>
        </div>
      </div>

      {/* Viewport HUD Controls */}
      <div className="absolute top-4 right-4 glass-panel p-2 rounded-lg border border-slate-800 flex flex-col space-y-2 z-20">
        <button 
          onClick={() => setZoom((z) => Math.min(z + 0.1, 1.5))}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button 
          onClick={() => setZoom((z) => Math.max(z - 0.1, 0.7))}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button 
          onClick={() => setZoom(1.0)}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
          title="Reset Camera"
        >
          <RotateCw className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}