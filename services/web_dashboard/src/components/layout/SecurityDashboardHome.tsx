import React, { useState } from "react";
import { MasterDashboardSummaryPayload } from "../../types/summary";
import { NavigationRouteId } from "../../types/dashboard";
import { KpiGrid } from "../overview/KpiGrid";
import { CriticalAssetsPanel } from "../overview/CriticalAssetsPanel";
import { SimulationControlBar } from "../simulation/SimulationControlBar";
import { TopologyControls } from "../topology/TopologyControls";
import { DeviceDetailFlyout } from "../topology/DeviceDetailFlyout";
import { TopologyNodePoint } from "../../types/topology";
import { TrafficMetricCards } from "../traffic/TrafficMetricCards";
import { ProtocolDistributionChart } from "../traffic/ProtocolDistributionChart";
import { TrafficTimelineChart } from "../traffic/TrafficTimelineChart";
import { ThreatTimelineStream } from "../threats/ThreatTimelineStream";
import { TimelineFilterBar } from "../threats/TimelineFilterBar";
import { EventDetailDrawer } from "../threats/EventDetailDrawer";
import { ThreatTimelineEvent, TimelineCategory } from "../../types/timeline";
import { ThreatHorizonGauges } from "../predictions/ThreatHorizonGauges";
import { ShapContributionBars } from "../predictions/ShapContributionBars";
import { ExplanationChainCard } from "../predictions/ExplanationChainCard";

interface SecurityDashboardHomeProps {
  data: MasterDashboardSummaryPayload;
  onNavigate: (route: NavigationRouteId) => void;
  onIsolateDevice: (deviceId: string) => void;
}

export const SecurityDashboardHome: React.FC<SecurityDashboardHomeProps> = ({
  data,
  onNavigate,
  onIsolateDevice
}) => {
  // Topology states
  const [selectedNode, setSelectedNode] = useState<TopologyNodePoint | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedZone, setSelectedZone] = useState("ALL");
  const [highlightPath, setHighlightPath] = useState(true);

  // Timeline states
  const [selectedEvent, setSelectedEvent] = useState<ThreatTimelineEvent | null>(null);
  const [timelineCategory, setTimelineCategory] = useState<TimelineCategory>("ALL");
  const [timelineSeverity, setTimelineSeverity] = useState("ALL");
  const [timelineSearch, setTimelineSearch] = useState("");

  // Simulation controls state
  const [simControl, setSimControl] = useState(data.simulationControl);

  return (
    <div className="space-y-4 p-4 max-w-[1700px] mx-auto pb-16">
      {/* 1. Executive KPI Metrics Row */}
      <KpiGrid data={data.kpis} onNavigate={onNavigate} />

      {/* 2. Simulation Engine Control Bar */}
      <SimulationControlBar
        state={simControl}
        onStart={() => setSimControl({ ...simControl, status: "RUNNING" })}
        onPause={() => setSimControl({ ...simControl, status: "PAUSED" })}
        onStop={() => setSimControl({ ...simControl, status: "STOPPED" })}
        onReset={() => setSimControl({ ...simControl, status: "RESET", elapsedSimulationTime: "00:00:00" })}
        onSelectScenario={(sc) => setSimControl({ ...simControl, activeScenario: sc })}
        onSetSpeed={(spd) => setSimControl({ ...simControl, speedMultiplier: spd })}
      />

      {/* 3. Live Network Topology Visual Canvas */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="p-3 border-b border-border flex justify-between items-center bg-muted/20">
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <strong className="text-foreground uppercase tracking-wider">Live Network Topology</strong>
            <span className="text-muted-foreground">({data.topology.totalNodes} Nodes, {data.topology.totalEdges} Directed Edges)</span>
          </div>
          {data.topAttackPath.criticalTarget && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-destructive/15 text-destructive border border-destructive/30">
              Active Traversal Targeting {data.topAttackPath.route[data.topAttackPath.route.length - 1]}
            </span>
          )}
        </div>

        <TopologyControls
          searchTerm={searchTerm}
          selectedZone={selectedZone}
          highlightAttackPath={highlightPath}
          onSearchChange={setSearchTerm}
          onZoneChange={setSelectedZone}
          onToggleHighlight={setHighlightPath}
          onZoomIn={() => {}}
          onZoomOut={() => {}}
          onReset={() => {}}
        />

        {/* Topology Schematic Canvas */}
        <div className="h-[360px] bg-background relative flex items-center justify-center p-4 overflow-hidden select-none">
          <svg className="w-full h-full max-w-[850px] max-h-[340px]" viewBox="0 0 800 620">
            {/* Zone Boundaries */}
            {data.topology.zones.map((z) => (
              <g key={z.zone}>
                <rect
                  x={z.x}
                  y={z.y}
                  width={z.width}
                  height={z.height}
                  rx="6"
                  fill={z.color}
                  stroke="rgba(255,255,255,0.08)"
                  strokeDasharray="4 4"
                />
                <text x={z.x + 12} y={z.y + 20} fill="#888" fontSize="10" fontFamily="monospace" fontWeight="bold">
                  {z.label}
                </text>
              </g>
            ))}

            {/* Edge Paths */}
            {data.topology.edges.map((e) => {
              const src = data.topology.nodes.find((n) => n.deviceId === e.source);
              const dst = data.topology.nodes.find((n) => n.deviceId === e.target);
              if (!src || !dst) return null;
              const isHl = highlightPath && e.isHighlighted;
              return (
                <line
                  key={e.id}
                  x1={src.x}
                  y1={src.y}
                  x2={dst.x}
                  y2={dst.y}
                  stroke={isHl ? "#f59e0b" : e.reachability === "BLOCKED" ? "#ef4444" : "#4b5563"}
                  strokeWidth={isHl ? 3 : 1.5}
                  strokeDasharray={e.reachability === "BLOCKED" ? "3 3" : undefined}
                />
              );
            })}

            {/* Nodes */}
            {data.topology.nodes.map((n) => (
              <g
                key={n.id}
                transform={`translate(${n.x}, ${n.y})`}
                onClick={() => setSelectedNode(n)}
                className="cursor-pointer"
              >
                <circle
                  r="20"
                  fill="#18181b"
                  stroke={n.riskLevel === "CRITICAL" ? "#ef4444" : n.riskLevel === "HIGH" ? "#f97316" : "#3b82f6"}
                  strokeWidth={n.isHighlighted ? 3.5 : 2}
                />
                <text textAnchor="middle" dy="4" fill="#fff" fontSize="9" fontFamily="monospace" fontWeight="bold">
                  {n.deviceId.substring(0, 7)}
                </text>
              </g>
            ))}
          </svg>
        </div>
      </div>

      {/* Critical Assets Strip */}
      <CriticalAssetsPanel assets={data.kpis.criticalAssets} onNavigate={onNavigate} />

      {/* 4. Traffic Monitoring + Threat Timeline Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left: Traffic Monitoring */}
        <div className="space-y-3">
          <TrafficMetricCards
            packetRateFormatted={data.traffic.packetRateFormatted}
            byteRateFormatted={data.traffic.byteRateFormatted}
            totalVolumeFormatted={data.traffic.totalVolumeFormatted}
            connections={data.traffic.connections}
          />
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 h-[280px]">
            <TrafficTimelineChart timeline={data.traffic.timeline} anomaly={data.traffic.anomaly} />
            <ProtocolDistributionChart protocols={data.traffic.protocols} />
          </div>
        </div>

        {/* Right: Threat Timeline Stream */}
        <div className="rounded-lg border border-border bg-card flex flex-col justify-between overflow-hidden">
          <div>
            <div className="p-3 border-b border-border flex justify-between items-center bg-muted/20">
              <span className="font-mono text-xs font-semibold text-foreground uppercase tracking-wider">
                Threat Timeline Stream
              </span>
              <span className="text-[10px] font-mono text-muted-foreground">
                {data.timeline.filteredCount} / {data.timeline.totalEvents} Events
              </span>
            </div>
            <TimelineFilterBar
              activeCategory={timelineCategory}
              activeSeverity={timelineSeverity}
              searchTerm={timelineSearch}
              onSelectCategory={setTimelineCategory}
              onSelectSeverity={setTimelineSeverity}
              onSearchChange={setTimelineSearch}
            />
            <div className="h-[280px] overflow-y-auto">
              <ThreatTimelineStream
                events={data.timeline.events}
                selectedEventId={selectedEvent?.eventId}
                onSelectEvent={setSelectedEvent}
              />
            </div>
          </div>
        </div>
      </div>

      {/* 5. Predictions & Explainable AI (XAI) Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ThreatHorizonGauges
          currentThreat={data.prediction.currentThreatProbability}
          currentThreatFormatted={data.prediction.currentThreatFormatted}
          futureThreat={data.prediction.futureThreatProbability}
          futureThreatFormatted={data.prediction.futureThreatFormatted}
          earlyWarningState={data.prediction.earlyWarningState}
          earlyWarningMessage={data.prediction.earlyWarningMessage}
          predictedCategory={data.prediction.predictedCategory}
          categoryConfidenceFormatted={data.prediction.categoryConfidenceFormatted}
          riskLevel={data.prediction.riskLevel}
        />

        <ShapContributionBars features={data.prediction.topFeatures} />

        <ExplanationChainCard
          explanation={data.prediction.naturalLanguageExplanation}
          chain={data.prediction.explanationChain}
          model={data.prediction.model}
          disclaimer={data.prediction.disclaimer}
        />
      </div>

      {/* Slide-over Inspection Drawers */}
      <DeviceDetailFlyout
        device={selectedNode}
        onClose={() => setSelectedNode(null)}
        onIsolate={onIsolateDevice}
      />

      <EventDetailDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        onNavigate={onNavigate}
      />
    </div>
  );
};