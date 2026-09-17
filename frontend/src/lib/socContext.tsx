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
  | "AUDIT_ENTRY"
  | "CVE";

export interface SearchResultItem {
  id: string;
  type: EntityType;
  title: string;
  subtitle: string;
  route: string;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
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
  isCommandPaletteOpen: boolean;
  setIsCommandPaletteOpen: (open: boolean) => void;

  isTriageDrawerOpen: boolean;
  setIsTriageDrawerOpen: (open: boolean) => void;
  isDbDisconnectedModalOpen: boolean;
  setIsDbDisconnectedModalOpen: (open: boolean) => void;

  pageState: PageLoadState;
  setPageState: (state: PageLoadState) => void;
  realtimeStatus: "CONNECTED" | "DISCONNECTED" | "RECONNECTING" | "STALE DATA" | "BACKEND ERROR";
  setRealtimeStatus: (status: "CONNECTED" | "DISCONNECTED" | "RECONNECTING" | "STALE DATA" | "BACKEND ERROR") => void;
}

const SocContext = createContext<SocContextType | undefined>(undefined);

export const GLOBAL_ENTITIES_INDEX: SearchResultItem[] = [
  { id: "WEB-01", type: "DEVICE", title: "web-01.dmz.internal", subtitle: "10.0.2.99 - Compromised", route: "/network-twin", severity: "CRITICAL" },
  { id: "DB-01", type: "DEVICE", title: "db-01.database.internal", subtitle: "10.0.3.10 - Database Tier", route: "/network-twin", severity: "HIGH" },
  { id: "CLIENT-01", type: "DEVICE", title: "client-01.corp.internal", subtitle: "10.0.1.25 - Workstation", route: "/network-twin", severity: "MEDIUM" },
  { id: "CORE-RTR-01", type: "DEVICE", title: "core-rtr-01.internal", subtitle: "10.0.1.1 - Core Gateway", route: "/network-twin", severity: "INFO" },
  { id: "ALT-20260916-001", type: "ALERT", title: "ALT-20260916-001 (Slowloris Flood)", subtitle: "Target: WEB-01:80 (Suricata SID:200142)", route: "/alerts", severity: "CRITICAL" },
  { id: "ALT-20260916-002", type: "ALERT", title: "ALT-20260916-002 (Port Anomaly Sweep)", subtitle: "Target: CLIENT-01 Inbound Sweep", route: "/alerts", severity: "HIGH" },
  { id: "CVE-2026-38408", type: "CVE", title: "CVE-2026-38408 (CVSS 9.8)", subtitle: "OpenSSH PKCS#11 Remote Code Execution", route: "/governance/reports", severity: "CRITICAL" },
  { id: "INC-2026-0916-001", type: "INCIDENT", title: "INC-2026-0916-001 (Lateral Infiltration)", subtitle: "WEB-01 -> DB-01 Unauthorized Pivot", route: "/incidents", severity: "CRITICAL" },
  { id: "PRD-20260916-0098", type: "PREDICTION", title: "Lateral Movement Forecast (96.4%)", subtitle: "Lead Time: 18.4s - Impact Stage", route: "/predictions", severity: "CRITICAL" },
  { id: "PATH-CLIENT-WEB-DB", type: "ATTACK_PATH", title: "CLIENT-01 -> WEB-01 -> DB-01", subtitle: "Risk Score: 78.4 | Status: ACTIVE_SIMULATED", route: "/attack-paths", severity: "CRITICAL" },
];

export function SocProvider({ children }: { children: React.ReactNode }) {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>("WEB-01");
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedPredictionId, setSelectedPredictionId] = useState<string | null>(null);
  const [selectedAttackPathId, setSelectedAttackPathId] = useState<string | null>(null);
  
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchResultItem[]>([]);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [isTriageDrawerOpen, setIsTriageDrawerOpen] = useState(false);
  const [isDbDisconnectedModalOpen, setIsDbDisconnectedModalOpen] = useState(false);

  const [pageState, setPageState] = useState<PageLoadState>("LOADED");
  const [realtimeStatus, setRealtimeStatus] = useState<"CONNECTED" | "DISCONNECTED" | "RECONNECTING" | "STALE DATA" | "BACKEND ERROR">("CONNECTED");

  const performGlobalSearch = (term: string): SearchResultItem[] => {
    if (!term.trim()) {
      setSearchResults([]);
      return [];
    }
    const lower = term.toLowerCase();
    const matched = GLOBAL_ENTITIES_INDEX.filter(
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

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setIsCommandPaletteOpen((prev) => !prev);
      }
      if (e.key === "Escape") {
        setIsCommandPaletteOpen(false);
        setIsTriageDrawerOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

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
        isCommandPaletteOpen,
        setIsCommandPaletteOpen,
        isTriageDrawerOpen,
        setIsTriageDrawerOpen,
        isDbDisconnectedModalOpen,
        setIsDbDisconnectedModalOpen,
        pageState,
        setPageState,
        realtimeStatus,
        setRealtimeStatus
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