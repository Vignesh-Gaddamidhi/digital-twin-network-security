"use client";
import React from "react";
import SocSidebar from "@/components/SocSidebar";
import SocHeader from "@/components/SocHeader";

export default function Page() {
  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      <SocSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <SocHeader pageTitle="Explainable AI (SHAP Feature Importance)" />
        <div className="flex-1 p-6 overflow-y-auto space-y-4">
          <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
            <h3 className="text-base font-bold text-slate-900 mb-2">Explainable AI (SHAP Feature Importance)</h3>
            <p className="text-xs text-slate-500">Live streaming operational view for digital twin security telemetry.</p>
          </div>
        </div>
      </main>
    </div>
  );
}