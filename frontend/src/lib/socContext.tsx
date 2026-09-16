"use client";

import React, { createContext, useContext, useState, useEffect } from "react";

export type EntityType = 
  | "DEVICE"
  | "ALERT"
  | "INCIDENT"
  | "PREDICTION"
  | "THREAT"
  | "ATTACK_PATH"
  | "SIMULATION"
  | "AUDIT_ENTRY";

export interface SearchResultItem {
  id: string;
  type: EntityType;
  title: string;
  subtitle: string;
  route: string;
  severity?: string;
}

export type PageLoadState = 
  | "LOADING" 
  | "LOADED" 
  | "EMPTY" 
  | "ERROR" 
  | "REFRESHING" 
  | "UNAVAILABLE" 
  | "STALE";

export interface SocContextType {
  selectedDeviceId: string | null;
  setSelectedDeviceId: (id: string | null) => void;
  selectedAlertId: string | null;
  setSelectedAlertId: (id: string | null) => void;
  selectedIncidentId: string | null;
  setSelectedIncidentId: (id: string | null) => void;
  selectedPredictionId: string | null;
  setSelectedPredictionId: (id: string | null) => void;
  selectedAttackPathId: string | null;
  setSelectedAttackPathId: (id: string | null) => void;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  searchResults: SearchResultItem[];
  performGlobalSearch: (term: string) => SearchResultItem[];
  pageState: PageLoadState;
  setPageState: (state: PageLoadState) => void;
  realtimeStatus: "CONNECTED" | "DISCONNECTED" | "RECONNECTING" | "STALE DATA" | "BACKEND ERROR";
}

const SocContext = createContext<SocContextType | undefined>(undefined);

export const GLOBAL_MOCK_INDEX: SearchResultItem[] = [
  { id: "WEB-01", type: "DEVICE", title: "web-01.dmz.internal", subtitle: "DMZ Web Server (10.0.2.99)", route: "/network-twin", severity: "CRITICAL" },
  { id: "DB-01", type: "DEVICE", title: "db-01.database.internal", subtitle: "Primary DB Cluster (10.0.3.10)", route: "/network-twin", severity: "HIGH" },
  { id: "CLIENT-01", type: "DEVICE", title: "client-01.corp.internal", subtitle: "Workstation (10.0.1.25)", route: "/network-twin", severity: "MEDIUM" },
  { id: "ALERT-20260916-001", type: "ALERT", title: "Unauthorized SQL Injection Probe", subtitle: "Target: WEB-01 Port 80", route: "/alerts", severity: "CRITICAL" },
  { id: "ALERT-20260916-002", type: "ALERT", title: "Port Anomaly Sweep", subtitle: "Target: CLIENT-01 Sweep", route: "/alerts", severity: "HIGH" },
  { id: "INC-20260916-0012", type: "INCIDENT", title: "Critical Multi-Hop Lateral Pivot", subtitle: "Involves WEB-01, DB-01 (3 correlated alerts)", route: "/incidents", severity: "CRITICAL" },
  { id: "PRD-20260916-0098", type: "PREDICTION", title: "Lateral Movement Forecast (96.4%)", subtitle: "Model: Random Forest + LSTM v2.4.0", route: "/predictions", severity: "CRITICAL" },
  { id: "PATH-CLIENT-WEB-DB", type: "ATTACK_PATH", title: "CLIENT-01 ➔ WEB-01 ➔ DB-01", subtitle: "Risk Score: 80.4 | Status: REACHABLE", route: "/attack-paths", severity: "CRITICAL" },
  { id: "SIM-RUN-156", type: "SIMULATION", title: "SYN Flood Saturation Run #156", subtitle: "1,450 pkts/s synthetic injection", route: "/attack-simulation", severity: "INFO" },
  { id: "AUD-1D1DEDC1", type: "AUDIT_ENTRY", title: "ISOLATE_DEVICE on WEB-01", subtitle: "Operator: SOC_SENIOR_ANALYST (Mode: SIMULATION)", route: "/governance/audit-logs", severity: "LOW" }
];

export function SocProvider({ children }: { children: React.ReactNode }) {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>("WEB-01");
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedPredictionId, setSelectedPredictionId] = useState<string | null>(null);
  const [selectedAttackPathId, setSelectedAttackPathId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchResultItem[]>([]);
  const [pageState, setPageState] = useState<PageLoadState>("LOADED");
  const [realtimeStatus, setRealtimeStatus] = useState<"CONNECTED" | "DISCONNECTED" | "RECONNECTING" | "STALE DATA" | "BACKEND ERROR">("CONNECTED");

  const performGlobalSearch = (term: string): SearchResultItem[] => {
    if (!term.trim()) {
      setSearchResults([]);
      return [];
    }
    const lower = term.toLowerCase();
    const matched = GLOBAL_MOCK_INDEX.filter(
      (item) =>
        item.id.toLowerCase().includes(lower) ||
        item.title.toLowerCase().includes(lower) ||
        item.subtitle.toLowerCase().includes(lower) ||
        item.type.toLowerCase().includes(lower)
    );
    setSearchResults(matched);
    return matched;
  };

  useEffect(() => {
    performGlobalSearch(searchQuery);
  }, [searchQuery]);

  return (
    <SocContext.Provider
      value={{
        selectedDeviceId,
        setSelectedDeviceId,
        selectedAlertId,
        setSelectedAlertId,
        selectedIncidentId,
        setSelectedIncidentId,
        selectedPredictionId,
        setSelectedPredictionId,
        selectedAttackPathId,
        setSelectedAttackPathId,
        searchQuery,
        setSearchQuery,
        searchResults,
        performGlobalSearch,
        pageState,
        setPageState,
        realtimeStatus
      }}
    >
      {children}
    </SocContext.Provider>
  );
}

export function useSoc() {
  const context = useContext(SocContext);
  if (!context) throw new Error("useSoc must be used within a SocProvider");
  return context;
}