"use client";

import React from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Check, X } from "lucide-react";

export default function RolesPage() {
  const roles = [
    {
      role: "ADMIN",
      desc: "Full administrative configuration, model retraining, and operator account management.",
      users: 1,
      perms: { viewConsole: true, triageAlerts: true, executeSim: true, modifySettings: true, editUsers: true }
    },
    {
      role: "SECURITY_LEAD",
      desc: "Incident closure authority, defensive policy overrides, and risk model recalibration.",
      users: 1,
      perms: { viewConsole: true, triageAlerts: true, executeSim: true, modifySettings: false, editUsers: false }
    },
    {
      role: "SOC_ANALYST",
      desc: "Daily operational alert triage, investigative queries, and simulated playbook dispatch.",
      users: 1,
      perms: { viewConsole: true, triageAlerts: true, executeSim: true, modifySettings: false, editUsers: false }
    },
    {
      role: "AUDITOR",
      desc: "Read-only access to tamper-evident forensic ledgers, reports, and compliance exports.",
      users: 1,
      perms: { viewConsole: true, triageAlerts: false, executeSim: false, modifySettings: false, editUsers: false }
    },
    {
      role: "VIEWER",
      desc: "Restricted read-only visibility into executive KPIs and sanitized network topology.",
      users: 1,
      perms: { viewConsole: true, triageAlerts: false, executeSim: false, modifySettings: false, editUsers: false }
    }
  ];

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Role-Based Access Control (RBAC) Matrix" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          <div className="glass-panel p-5">
            <h3 className="text-sm font-bold text-slate-900 mb-1">Enterprise Access Control Policy</h3>
            <p className="text-xs text-slate-500">
              Role permissions mapped across Operational Modules, Playbook Execution, and Governance Ledgers.
            </p>
          </div>

          <div className="glass-panel overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Role Designation</th>
                  <th className="py-3 px-4">Assigned Operators</th>
                  <th className="py-3 px-4 text-center">View Console</th>
                  <th className="py-3 px-4 text-center">Triage Alerts</th>
                  <th className="py-3 px-4 text-center">Execute Playbooks</th>
                  <th className="py-3 px-4 text-center">Modify Settings</th>
                  <th className="py-3 px-4 text-center">Manage Users</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {roles.map((r) => (
                  <tr key={r.role} className="hover:bg-slate-50/80 transition">
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-slate-900 font-mono">{r.role}</div>
                      <div className="text-[11px] text-slate-500 font-sans">{r.desc}</div>
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold text-slate-700">{r.users}</td>
                    <td className="py-3.5 px-4 text-center">
                      <Check className="w-4 h-4 text-emerald-600 mx-auto" />
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      {r.perms.triageAlerts ? <Check className="w-4 h-4 text-emerald-600 mx-auto" /> : <X className="w-4 h-4 text-slate-300 mx-auto" />}
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      {r.perms.executeSim ? <Check className="w-4 h-4 text-emerald-600 mx-auto" /> : <X className="w-4 h-4 text-slate-300 mx-auto" />}
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      {r.perms.modifySettings ? <Check className="w-4 h-4 text-emerald-600 mx-auto" /> : <X className="w-4 h-4 text-slate-300 mx-auto" />}
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      {r.perms.editUsers ? <Check className="w-4 h-4 text-emerald-600 mx-auto" /> : <X className="w-4 h-4 text-slate-300 mx-auto" />}
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