"use client";

import React, { useState } from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";
import { Users, UserPlus, ShieldCheck, Mail, Clock } from "lucide-react";

export default function UsersPage() {
  const users = [
    { id: "USR-001", name: "Sarah Connor", username: "sconnor", role: "ADMIN", status: "ACTIVE", lastActivity: "2 mins ago", createdAt: "2026-01-15" },
    { id: "USR-002", name: "Marcus Wright", username: "mwright", role: "SECURITY_LEAD", status: "ACTIVE", lastActivity: "12 mins ago", createdAt: "2026-02-01" },
    { id: "USR-003", name: "Kyle Reese", username: "kreese", role: "SOC_ANALYST", status: "ACTIVE", lastActivity: "Just now", createdAt: "2026-03-10" },
    { id: "USR-004", name: "Miles Dyson", username: "mdyson", role: "AUDITOR", status: "INACTIVE", lastActivity: "4 days ago", createdAt: "2026-04-20" },
    { id: "USR-005", name: "John Connor", username: "jconnor", role: "VIEWER", status: "ACTIVE", lastActivity: "1 hour ago", createdAt: "2026-05-12" }
  ];

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Authorized SOC Operators & Credential Management" />

        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Header Action Bar */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
            <div className="text-xs font-semibold text-slate-500">
              Total Operator Accounts: <span className="font-bold text-slate-900">{users.length}</span>
            </div>
            <button className="flex items-center space-x-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg transition">
              <UserPlus className="w-3.5 h-3.5" />
              <span>Provision Operator</span>
            </button>
          </div>

          {/* Users Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">User ID</th>
                  <th className="py-3 px-4">Full Name</th>
                  <th className="py-3 px-4">Username</th>
                  <th className="py-3 px-4">Assigned Role</th>
                  <th className="py-3 px-4">Account Status</th>
                  <th className="py-3 px-4">Last Activity</th>
                  <th className="py-3 px-4">Created Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4 font-mono font-bold text-blue-600">{u.id}</td>
                    <td className="py-3 px-4 font-bold text-slate-900">{u.name}</td>
                    <td className="py-3 px-4 font-mono text-slate-500">{u.username}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-purple-50 text-purple-700 border border-purple-200">
                        {u.role}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        u.status === "ACTIVE" ? "bg-emerald-100 text-emerald-700" : "bg-slate-100 text-slate-500"
                      }`}>
                        {u.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-500">{u.lastActivity}</td>
                    <td className="py-3 px-4 font-mono text-slate-400">{u.createdAt}</td>
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