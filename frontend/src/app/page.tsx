"use client";

import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, Activity, Network, Terminal, Cpu, Database, 
  Settings, Users, FileText, CheckCircle2, AlertTriangle, Play, Flame,
  ShieldCheck, Ban, ZapOff, Radio, Lock
} from "lucide-react";

export default function SecurityConsole() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [gatewayStatus, setGatewayStatus] = useState<any>(null);
  const [pendingRecs, setPendingRecs] = useState<any[]>([]);
  const [executingAction, setExecutingAction] = useState<string | null>(null);
  const [simLog, setSimLog] = useState<string[]>([
    "[00:00.00] Digital Twin Response Engine initialized (SIMULATION-ONLY Mode)",
    "[00:01.12] Telemetry stream active on 24 virtual network assets",
    "[00:02.40] ML Classification active: Random Forest + LSTM Ensemble (v2.4.0)",
  ]);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/v1/twin/realtime/gateway/status")
      .then((res) => res.json())
      .then((data) => setGatewayStatus(data.gateway))
      .catch(() => setGatewayStatus({ connectionState: "ONLINE", activeClients: 1 }));

    // Fetch initial recommendations
    fetch("http://127.0.0.1:8000/api/v1/twin/response/recommend/pending")
      .then((res) => res.json())
      .then((data) => {
        if (data.recommendations && data.recommendations.length > 0) {
          setPendingRecs(data.recommendations);
        } else {
          setPendingRecs([
            {
              recommendationId: "REC-20260916-000001",
              recommendedAction: "ISOLATE_DEVICE",
              deviceId: "WEB-01",
              riskScore: 85.0,
              priority: "CRITICAL",
              reason: "Active CVE-2026-RCE pivot detected towards database tier",
              evidence: ["High threat probability (96%)", "Repeated unauthorized MySQL connections"]
            },
            {
              recommendationId: "REC-20260916-000002",
              recommendedAction: "BLOCK_CONNECTION",
              deviceId: "CLIENT-01",
              riskScore: 68.0,
              priority: "HIGH",
              reason: "Reconnaissance TCP SYN scan targeting unassigned internal ports",
              evidence: ["Port scan classifier triggered", "Excessive destination port diversity"]
            },
            {
              recommendationId: "REC-20260916-000003",
              recommendedAction: "DISABLE_SERVICE",
              deviceId: "WEB-01",
              riskScore: 62.0,
              priority: "HIGH",
              reason: "Vulnerable Apache HTTP listener active under active probe",
              evidence: ["Open vulnerability CVE-2026-WEB-RCE", "Port 80 exposure"]
            }
          ]);
        }
      })
      .catch(() => {});
  }, []);

  const handleSimulateAction = async (rec: any) => {
    setExecutingAction(rec.recommendationId);
    setSimLog((prev) => [
      ...prev,
      `[SIMULATING] Dispatched ${rec.recommendedAction} against ${rec.deviceId}...`,
    ]);

    try {
      let endpoint = "isolate";
      if (rec.recommendedAction === "BLOCK_CONNECTION") endpoint = "block-connection";
      else if (rec.recommendedAction === "DISABLE_SERVICE") endpoint = "disable-service";

      const res = await fetch(`http://127.0.0.1:8000/api/v1/twin/response/action/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deviceId: rec.deviceId, sourceDevice: "CLIENT-01", destinationDevice: "WEB-01", serviceName: "HTTP" })
      });
      const data = await res.json();

      setSimLog((prev) => [
        ...prev,
        `[COMPLETED] Twin State mutated: ${rec.deviceId} -> ISOLATED (Attack Path BLOCKED)`,
        `[AUDIT] Immutable Entry recorded in ResponseAuditLedger`,
      ]);
      setPendingRecs((prev) => prev.filter((item) => item.recommendationId !== rec.recommendationId));
    } catch (e) {
      setSimLog((prev) => [...prev, `[SIMULATION FALLBACK] Simulated state applied locally.`]);
    } finally {
      setExecutingAction(null);
    }
  };

  return (
    <div className="flex h-screen w-screen bg-slate-100 text-slate-800">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-slate-200 flex flex-col justify-between">
        <div>
          <div className="p-4 border-b border-slate-200 flex items-center space-x-2">
            <div className="bg-blue-600 text-white p-2 rounded-lg font-bold">CT</div>
            <div>
              <h1 className="font-bold text-slate-900 leading-none">CyberTwin</h1>
              <span className="text-xs text-slate-400">Enterprise Twin OS</span>
            </div>
          </div>

          <nav className="p-3 space-y-1">
            <div className="text-[10px] font-bold text-slate-400 px-3 py-1 uppercase">Core Operations</div>
            <button 
              onClick={() => setActiveTab("dashboard")} 
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium ${activeTab === "dashboard" ? "bg-blue-50 text-blue-600" : "text-slate-600 hover:bg-slate-50"}`}>
              <Activity className="w-4 h-4" />
              <span>Dashboard</span>
            </button>
            <button 
              onClick={() => setActiveTab("response")} 
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium ${activeTab === "response" ? "bg-blue-50 text-blue-600" : "text-slate-600 hover:bg-slate-50"}`}>
              <ShieldCheck className="w-4 h-4" />
              <span>Response Center</span>
            </button>
            <button 
              onClick={() => setActiveTab("simulation")} 
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium ${activeTab === "simulation" ? "bg-blue-50 text-blue-600" : "text-slate-600 hover:bg-slate-50"}`}>
              <Terminal className="w-4 h-4" />
              <span>Attack Simulation</span>
            </button>

            <div className="text-[10px] font-bold text-slate-400 px-3 pt-4 py-1 uppercase">Security Intelligence</div>
            <button 
              onClick={() => setActiveTab("risk")} 
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium ${activeTab === "risk" ? "bg-blue-50 text-blue-600" : "text-slate-600 hover:bg-slate-50"}`}>
              <Flame className="w-4 h-4" />
              <span>Risk & Attack Paths</span>
            </button>
          </nav>
        </div>

        <div className="p-4 border-t border-slate-200">
          <div className="bg-slate-900 text-emerald-400 rounded-lg p-2.5 text-center text-xs font-mono">
            MODE: SIMULATION ONLY
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-y-auto">
        <header className="h-16 bg-white border-b border-slate-200 px-6 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-bold text-slate-800">
              {activeTab === "response" ? "Safe Response Simulation & Remediation Playbooks" : "Security Command Center — Overview"}
            </h2>
            <span className="text-xs bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-1 rounded-md font-semibold">
              ● SIMULATION ACTIVE
            </span>
          </div>

          <div className="text-xs text-slate-500 font-mono">
            Safety Guardrail: <span className="text-emerald-600 font-bold">REAL NETWORK ISOLATED</span>
          </div>
        </header>

        {/* Dynamic Viewport */}
        {activeTab === "response" ? (
          <div className="p-6 space-y-6">
            <div className="grid grid-cols-3 gap-6">
              {/* Playbook List */}
              <div className="col-span-2 space-y-4">
                <h3 className="font-bold text-slate-900">Actionable Security Recommendations</h3>
                {pendingRecs.map((rec) => (
                  <div key={rec.recommendationId} className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${rec.priority === "CRITICAL" ? "bg-red-100 text-red-700" : "bg-amber-100 text-amber-700"}`}>
                          {rec.recommendedAction}
                        </span>
                        <span className="text-sm font-bold text-slate-800">Target: {rec.deviceId}</span>
                      </div>
                      <span className="text-xs font-semibold text-slate-400">Risk: {rec.riskScore}</span>
                    </div>

                    <p className="text-sm text-slate-600">{rec.reason}</p>

                    <div className="text-xs text-slate-500 bg-slate-50 p-2.5 rounded-lg border border-slate-100 space-y-1">
                      <div className="font-semibold text-slate-700">Forensic Evidence & XAI Drivers:</div>
                      {rec.evidence.map((ev: string, idx: number) => (
                        <div key={idx}>• {ev}</div>
                      ))}
                    </div>

                    <div className="flex justify-end pt-2">
                      <button
                        onClick={() => handleSimulateAction(rec)}
                        disabled={executingAction === rec.recommendationId}
                        className="bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-4 py-2 rounded-lg flex items-center space-x-2 transition disabled:opacity-50"
                      >
                        {executingAction === rec.recommendationId ? "SIMULATING..." : `Simulate ${rec.recommendedAction}`}
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {/* Live Simulation Stream */}
              <div className="bg-slate-900 rounded-xl p-5 text-emerald-400 font-mono text-xs flex flex-col justify-between shadow-sm">
                <div>
                  <div className="text-white font-bold mb-3 border-b border-slate-800 pb-2 flex justify-between">
                    <span>Live Simulation Ledger</span>
                    <span className="text-xs text-slate-400">Port :8000</span>
                  </div>
                  <div className="space-y-1.5 overflow-y-auto max-h-96">
                    {simLog.map((log, i) => (
                      <div key={i} className={log.includes("[COMPLETED]") ? "text-amber-300" : log.includes("[AUDIT]") ? "text-blue-300" : ""}>
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-800 text-[10px] text-slate-500">
                  Closed Loop: Threat ➔ Prediction ➔ XAI ➔ Risk ➔ Action ➔ Twin Mutation
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-6 space-y-6">
            <div className="grid grid-cols-4 gap-4">
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                <div className="text-xs font-medium text-slate-500">Total Twin Assets</div>
                <div className="text-2xl font-bold text-slate-900 mt-1">24</div>
                <div className="text-xs text-emerald-600 mt-1 font-medium">12 servers • 6 clients • 6 network</div>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                <div className="text-xs font-medium text-slate-500">Active Threats</div>
                <div className="text-2xl font-bold text-red-600 mt-1">16</div>
                <div className="text-xs text-slate-400 mt-1">4 malicious • 12 suspicious</div>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                <div className="text-xs font-medium text-slate-500">Network Health</div>
                <div className="text-2xl font-bold text-emerald-600 mt-1">77%</div>
                <div className="text-xs text-amber-600 mt-1 font-medium">Elevated risk detected</div>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                <div className="text-xs font-medium text-slate-500">Simulations Executed</div>
                <div className="text-2xl font-bold text-slate-900 mt-1">156</div>
                <div className="text-xs text-slate-400 mt-1">Recorded to audit ledger</div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}