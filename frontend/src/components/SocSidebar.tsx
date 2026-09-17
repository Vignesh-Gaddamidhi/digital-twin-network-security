"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Network, ShieldAlert, Terminal, Flame, Route, BrainCircuit,
  BellRing, AlertOctagon, Cpu, Sparkles, History, LineChart, FileSpreadsheet,
  FileCheck2, Users, ShieldCheck, Settings
} from "lucide-react";

interface NavItem {
  label: string;
  href: string;
  icon: any;
  badge?: string;
  badgeColor?: string;
}

export default function SocSidebar() {
  const pathname = usePathname();

  const secOps: NavItem[] = [
    { label: "Dashboard", href: "/", icon: LayoutDashboard },
    { label: "Network Twin", href: "/network-twin", icon: Network },
    { label: "Threat Detection", href: "/threat-detection", icon: ShieldAlert },
    { label: "Attack Simulation", href: "/attack-simulation", icon: Terminal, badge: "SANDBOX", badgeColor: "bg-purple-900/60 text-purple-300 border-purple-700" },
    { label: "Risk Analysis", href: "/risk-analysis", icon: Flame },
    { label: "Attack Paths", href: "/attack-paths", icon: Route },
    { label: "Predictions", href: "/predictions", icon: BrainCircuit },
    { label: "Alerts", href: "/alerts", icon: BellRing, badge: "16", badgeColor: "bg-cyber-crimson/20 text-cyber-crimson border-cyber-crimson/40" },
    { label: "Incidents", href: "/incidents", icon: AlertOctagon, badge: "3", badgeColor: "bg-amber-900/60 text-amber-300 border-amber-700" },
  ];

  const intelligence: NavItem[] = [
    { label: "ML Models", href: "/intelligence/ml-models", icon: Cpu },
    { label: "XAI (SHAP)", href: "/intelligence/xai", icon: Sparkles },
    { label: "Threat Timeline", href: "/intelligence/threat-timeline", icon: History },
    { label: "Traffic Analytics", href: "/intelligence/traffic-analytics", icon: LineChart },
  ];

  const governance: NavItem[] = [
    { label: "Reports", href: "/governance/reports", icon: FileSpreadsheet },
    { label: "Audit Logs", href: "/governance/audit-logs", icon: FileCheck2 },
    { label: "Users", href: "/governance/users", icon: Users },
    { label: "Roles & RBAC", href: "/governance/roles", icon: ShieldCheck },
    { label: "Settings", href: "/governance/settings", icon: Settings },
  ];

  const renderNavSection = (title: string, items: NavItem[]) => (
    <div className="mb-4">
      <div className="text-[10px] font-mono font-bold text-slate-500 px-3 py-1.5 uppercase tracking-wider">
        {title}
      </div>
      <div className="space-y-1">
        {items.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono font-semibold transition border ${
                isActive
                  ? "bg-cyber-cyan/10 text-cyber-cyan border-cyber-cyan/40 shadow-cyan-glow"
                  : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <Icon className={`w-4 h-4 ${isActive ? "text-cyber-cyan" : "text-slate-400"}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono font-bold border ${item.badgeColor || "bg-slate-800 text-slate-300 border-slate-700"}`}>
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </div>
    </div>
  );

  return (
    <aside className="w-64 bg-obsidian-900 border-r border-slate-800 flex flex-col justify-between h-screen shrink-0 overflow-y-auto select-none">
      <div className="p-3">
        <div className="p-3 mb-2 flex items-center space-x-3 border-b border-slate-800/80">
          <div className="w-9 h-9 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/40 text-cyber-cyan flex items-center justify-center font-mono font-black text-base shadow-cyan-glow">
            CT
          </div>
          <div>
            <h1 className="font-mono font-black text-white text-sm tracking-tight leading-none">
              CyberTwin
            </h1>
            <span className="text-[10px] font-mono font-semibold text-cyber-cyan uppercase tracking-wider">
              Command Center v2.6
            </span>
          </div>
        </div>

        <nav>
          {renderNavSection("Security Operations", secOps)}
          {renderNavSection("Intelligence", intelligence)}
          {renderNavSection("Governance & Admin", governance)}
        </nav>
      </div>

      <div className="p-3 border-t border-slate-800/80 bg-obsidian-800/40">
        <div className="bg-obsidian-900 text-cyber-emerald border border-cyber-emerald/30 rounded-lg p-2 text-center text-[10px] font-mono font-bold shadow-emerald-glow tracking-wider">
          ● MODE: SIMULATION ONLY
        </div>
      </div>
    </aside>
  );
}