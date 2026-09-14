import React from "react";
import { ExecutiveKpiPayload } from "../../types/kpi";
import { NavigationRouteId } from "../../types/dashboard";
import { KpiCard } from "./KpiCard";

interface KpiGridProps {
  data: ExecutiveKpiPayload;
  onNavigate: (route: NavigationRouteId) => void;
}

export const KpiGrid: React.FC<KpiGridProps> = ({ data, onNavigate }) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* 1. DEVICES KPI */}
      <KpiCard
        title="Devices"
        value={data.devices.total}
        subtitle="Network inventory active"
        badgeText={`${data.devices.normal} Healthy`}
        badgeVariant="success"
        targetRoute="devices"
        onDrillDown={onNavigate}
        details={[
          { label: "Normal", count: data.devices.normal },
          { label: "At Risk", count: data.devices.atRisk },
          { label: "Suspicious", count: data.devices.suspicious },
          { label: "Isolated", count: data.devices.isolated }
        ]}
      />

      {/* 2. THREATS KPI */}
      <KpiCard
        title="Active Threats"
        value={data.threats.total}
        subtitle="Detected telemetry anomalies"
        badgeText={`${data.threats.critical} Critical`}
        badgeVariant={data.threats.critical > 0 ? "destructive" : "warning"}
        targetRoute="threats"
        onDrillDown={onNavigate}
        details={[
          { label: "Critical", count: data.threats.critical },
          { label: "High", count: data.threats.high },
          { label: "Medium", count: data.threats.medium },
          { label: "Low", count: data.threats.low }
        ]}
      />

      {/* 3. OVERALL RISK KPI */}
      <KpiCard
        title="Overall Risk"
        value={data.risk.level}
        subtitle={`Score: ${data.risk.scoreFormatted}`}
        badgeText={data.risk.trend}
        badgeVariant={data.risk.level === "CRITICAL" ? "destructive" : "warning"}
        targetRoute="risk"
        onDrillDown={onNavigate}
        details={[
          { label: "Highest Node", count: 1 },
          { label: "Asset Level", count: data.risk.score > 75 ? 4 : 3 }
        ]}
      />

      {/* 4. ACTIVE SCENARIOS / ATTACKS KPI */}
      <KpiCard
        title="Active Scenarios"
        value={data.attacks.activeCount}
        subtitle="Controlled simulations running"
        badgeText="SIMULATION"
        badgeVariant="default"
        targetRoute="attack-paths"
        onDrillDown={onNavigate}
        details={[
          { label: "Configured", count: data.attacks.totalConfigured },
          { label: "Active Paths", count: data.attacks.runningScenarios.length }
        ]}
      />
    </div>
  );
};