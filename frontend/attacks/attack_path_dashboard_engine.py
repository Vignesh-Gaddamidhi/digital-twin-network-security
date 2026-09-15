from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.graph_models import PathStatusEnum
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.discovery.discovery_models import DiscoveredPathDetail
from services.digital_twin.attack_path.analysis.master_attack_path_orchestrator import master_attack_path_orchestrator
from frontend.attacks.attack_path_dashboard_models import (
    PathFilterTypeEnum, AttackPathItemCard, TopologyHighlightState,
    AttackPathDetailedView, AttackPathDashboardSnapshot
)

class AttackPathDashboardEngine:
    """Orchestrates attack path ranking, topological highlighting, filtering, and cross-layer XAI linkages."""

    def __init__(self):
        self.active_filter: PathFilterTypeEnum = PathFilterTypeEnum.ALL
        self.selected_path_id: Optional[str] = None
        self._seed_default_analysis()

    def _seed_default_analysis(self):
        # Run master analysis between CLIENT-01 and DB-01
        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        self.cached_master_analysis = master_attack_path_orchestrator.run_master_analysis(
            source_device_id="CLIENT-01",
            target_device_id="DB-01",
            entry_threat_probability=0.88,
            attack_impact_weight=0.80,
            ml_threat_features=["connection frequency", "destination diversity", "port 443 ratio"]
        )
        if self.cached_master_analysis.rankedPaths:
            self.selected_path_id = self.cached_master_analysis.rankedPaths[0].pathId

    def generate_dashboard_snapshot(self, filter_type: PathFilterTypeEnum = PathFilterTypeEnum.ALL) -> AttackPathDashboardSnapshot:
        self.active_filter = filter_type
        raw_ranked = self.cached_master_analysis.rankedPaths

        item_cards: List[AttackPathItemCard] = []
        for p in raw_ranked:
            chain = p.nodeSequence
            reach = "REACHABLE" if p.status == "POSSIBLE" else p.status
            vulns = []
            services = []
            for nid in chain:
                if nid in attack_path_graph.nodes:
                    node = attack_path_graph.get_node(nid)
                    vulns.extend(node.vulnerabilities)
                    services.extend(node.services)

            card = AttackPathItemCard(
                pathId=p.pathId,
                rank=p.rank,
                entryPoint=chain[0],
                targetNode=chain[-1],
                nodeSequence=chain,
                hopCount=len(chain) - 1,
                reachability=reach,
                riskScore=p.riskScore,
                riskLevel=p.riskLevel,
                status=p.status,
                criticalTarget=p.criticalTarget,
                traversedServices=list(set(services)),
                vulnerabilitiesExposed=list(set(vulns)),
                shortExplanation=p.explanation
            )

            # Apply Filter
            if self._matches_filter(card, self.active_filter):
                item_cards.append(card)

        # Select target path detail
        sel_detail = None
        target_card = None
        if item_cards:
            if self.selected_path_id:
                target_card = next((c for c in item_cards if c.pathId == self.selected_path_id), item_cards[0])
            else:
                target_card = item_cards[0]

            self.selected_path_id = target_card.pathId
            sel_detail = self._build_detailed_view(target_card)

        return AttackPathDashboardSnapshot(
            totalDiscoveredPaths=len(raw_ranked),
            activeFilter=self.active_filter,
            rankedPaths=item_cards,
            selectedPathDetail=sel_detail
        )

    def _matches_filter(self, card: AttackPathItemCard, filter_type: PathFilterTypeEnum) -> bool:
        if filter_type == PathFilterTypeEnum.ALL:
            return True
        elif filter_type == PathFilterTypeEnum.HIGHEST_RISK:
            return card.riskLevel in (RiskLevelTier.HIGH, RiskLevelTier.CRITICAL)
        elif filter_type == PathFilterTypeEnum.CRITICAL_ASSETS:
            return card.criticalTarget is True
        elif filter_type == PathFilterTypeEnum.REACHABLE:
            return card.reachability == "REACHABLE"
        elif filter_type == PathFilterTypeEnum.BLOCKED:
            return card.status == "BLOCKED"
        elif filter_type == PathFilterTypeEnum.PARTIAL:
            return "PARTIAL" in card.status
        return True

    def select_path(self, path_id: str) -> AttackPathDashboardSnapshot:
        self.selected_path_id = path_id
        return self.generate_dashboard_snapshot(self.active_filter)

    def _build_detailed_view(self, card: AttackPathItemCard) -> AttackPathDetailedView:
        chain = card.nodeSequence
        
        # Build Topology Highlight State
        edge_ids = []
        severed = []
        for i in range(len(chain) - 1):
            u, v = chain[i], chain[i + 1]
            matching = [e for e in attack_path_graph.edges.values() if e.sourceNode == u and e.destinationNode == v]
            if matching:
                edge_ids.append(matching[0].edgeId)
                if not matching[0].reachable or matching[0].status == "BLOCKED":
                    severed.append(matching[0].edgeId)

        highlight = TopologyHighlightState(
            activePathId=card.pathId,
            highlightedNodes=chain,
            highlightedEdges=edge_ids,
            severedEdges=severed,
            targetNodeId=card.targetNode
        )

        xai_text = (
            f"The origin of this path on {card.entryPoint} was flagged by Random Forest "
            f"due to abnormal connection frequency and destination diversity."
        )

        recom = (
            f"Apply immediate network segmentation between {chain[-2]} and {card.targetNode} on exposed port."
            if card.reachability == "REACHABLE"
            else "Security control currently drops traffic. Maintain active audit monitoring."
        )

        return AttackPathDetailedView(
            selectedPath=card,
            highlightState=highlight,
            threatProbability=0.88,
            maxIntermediateRisk=69.6,
            targetCriticalityWeight=1.00 if card.criticalTarget else 0.40,
            vulnerabilityWeight=1.00 if len(card.vulnerabilitiesExposed) > 0 else 0.20,
            attackImpactWeight=0.80,
            xaiAttributionText=xai_text,
            originatingFeatures=["connection_frequency", "destination_diversity", "port_entropy"],
            recommendedContainment=recom
        )

attack_path_dashboard_engine = AttackPathDashboardEngine()