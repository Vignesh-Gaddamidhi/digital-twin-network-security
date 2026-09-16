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
}

export default function SocSidebar() {
  const pathname = usePathname();

  const secOps: NavItem[] = [
    { label: "Dashboard", href: "/", icon: LayoutDashboard },
    { label: "Network Twin", href: "/network-twin", icon: Network },
    { label: "Threat Detection", href: "/threat-detection", icon: ShieldAlert },
    { label: "Attack Simulation", href: "/attack-simulation", icon: Terminal, badge: "SANDBOX" },
    { label: "Risk Analysis", href: "/risk-analysis", icon: Flame },
    { label: "Attack Paths", href: "/attack-paths", icon: Route },
    { label: "Predictions", href: "/predictions", icon: BrainCircuit },
    { label: "Alerts", href: "/alerts", icon: BellRing, badge: "16" },
    { label: "Incidents", href: "/incidents", icon: AlertOctagon, badge: "3" },
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
      <div className="text-[10px] font-bold text-slate-400 px-3 py-1.5 uppercase tracking-wider">
        {title}
      </div>
      <div className="space-y-0.5">
        {items.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                isActive
                  ? "bg-blue-50 text-blue-600 shadow-sm border border-blue-100"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <Icon className={`w-4 h-4 ${isActive ? "text-blue-600" : "text-slate-400"}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                  item.badge === "SANDBOX" ? "bg-purple-100 text-purple-700" : "bg-red-100 text-red-700"
                }`}>
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
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col justify-between h-screen shrink-0 overflow-y-auto select-none">
      <div className="p-3">
        <div className="p-3 mb-2 flex items-center space-x-2.5 border-b border-slate-100">
          <div className="bg-blue-600 text-white p-2 rounded-lg font-bold text-sm shadow">CT</div>
          <div>
            <h1 className="font-extrabold text-slate-900 text-sm tracking-tight leading-none">CyberTwin</h1>
            <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Enterprise SOC v2.6</span>
          </div>
        </div>

        <nav>
          {renderNavSection("Security Operations", secOps)}
          {renderNavSection("Intelligence", intelligence)}
          {renderNavSection("Governance & Admin", governance)}
        </nav>
      </div>

      <div className="p-3 border-t border-slate-200 bg-slate-50">
        <div className="bg-slate-900 text-emerald-400 rounded-lg p-2 text-center text-[10px] font-mono shadow-inner">
          MODE: SIMULATION ONLY
        </div>
      </div>
    </aside>
  );
}