import json
from pathlib import Path
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[4]
VISUAL_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path"
EXP_REPORTS_FILE = VISUAL_ARTIFACTS_DIR / "path_explanations.json"

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.attack_path.graph.graph_models import (
    PathStatusEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.discovery.discovery_models import DiscoveredPathDetail
from services.digital_twin.attack_path.scoring.path_scoring_models import AttackPathRisk
from services.digital_twin.attack_path.scoring.path_risk_engine import path_risk_engine
from services.digital_twin.attack_path.visualization.path_visual_models import (
    PathVisualStateEnum, NodeVisualCard, EdgeVisualCard, AttackPathVisualPanel,
    GraphVisualizationFilter, ComprehensivePathExplanationReport
)

class AttackPathVisualEngine:
    """Provides visual presentation models, ASCII diagrams, node/edge inspection cards, and forensic explanations."""

    def __init__(self, artifacts_dir: Path = VISUAL_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.report_history: List[ComprehensivePathExplanationReport] = []

    def get_node_visual_card(self, device_id: str) -> NodeVisualCard:
        node = attack_path_graph.get_node(device_id)
        tier = threshold_classifier.classify(node.riskScore)
        return NodeVisualCard(
            deviceId=node.deviceId,
            hostname=node.hostname,
            zone=node.zone,
            deviceType=node.deviceType,
            assetCriticality=node.assetCriticality,
            riskScore=node.riskScore,
            riskLevel=tier,
            openPorts=node.exposedPorts,
            services=node.services,
            activeVulnerabilities=node.vulnerabilities,
            vulnerabilityCount=len(node.vulnerabilities),
            securityState=node.securityState,
            reachable=node.reachable
        )

    def get_edge_visual_card(self, source_id: str, destination_id: str) -> EdgeVisualCard:
        matching = [e for e in attack_path_graph.edges.values() if e.sourceNode == source_id and e.destinationNode == destination_id]
        if not matching:
            raise KeyError(f"No directed edge exists from '{source_id}' to '{destination_id}'.")
        e = matching[0]
        return EdgeVisualCard(
            edgeId=e.edgeId,
            sourceNode=e.sourceNode,
            destinationNode=e.destinationNode,
            directedNotation=f"{e.sourceNode} -> {e.destinationNode}",
            protocol=e.protocol,
            destinationPort=e.destinationPort,
            service=e.service,
            reachability="REACHABLE" if e.reachable else "BLOCKED",
            securityControl=e.securityControl or "Standard Zone Ingress",
            connectionId=e.connectionId
        )

    def determine_visual_state(self, path_status: PathStatusEnum, risk_level: RiskLevelTier) -> PathVisualStateEnum:
        if path_status == PathStatusEnum.BLOCKED:
            return PathVisualStateEnum.BLOCKED_PATH
        if risk_level == RiskLevelTier.CRITICAL:
            return PathVisualStateEnum.CRITICAL_PATH
        elif risk_level == RiskLevelTier.HIGH:
            return PathVisualStateEnum.HIGH_RISK_PATH
        elif risk_level == RiskLevelTier.MEDIUM:
            return PathVisualStateEnum.POTENTIAL_ATTACK_PATH
        else:
            return PathVisualStateEnum.NORMAL

    def render_ascii_path_diagram(self, node_chain: List[str], path_status: PathStatusEnum) -> str:
        lines = []
        arrow = " │\n ▼\n" if path_status != PathStatusEnum.BLOCKED else " │\n X (BLOCKED)\n ▼\n"
        for idx, nid in enumerate(node_chain):
            nd = attack_path_graph.get_node(nid)
            vuln_str = f" [Vulns: {len(nd.vulnerabilities)}]" if nd.vulnerabilities else ""
            lines.append(f"[{nd.nodeId}] ({nd.zone}, Crit: {nd.assetCriticality}){vuln_str}")
            if idx < len(node_chain) - 1:
                lines.append(arrow)
        return "".join(lines)

    def generate_path_visual_panel(
        self,
        path: DiscoveredPathDetail,
        risk_score_record: AttackPathRisk
    ) -> AttackPathVisualPanel:
        chain = path.nodeSequence
        vis_state = self.determine_visual_state(path.status, risk_score_record.level)

        return AttackPathVisualPanel(
            pathId=path.pathId,
            source=chain[0],
            entryNode=chain[1] if len(chain) > 1 else chain[0],
            targetNode=chain[-1],
            nodeSequence=chain,
            pathLength=path.hopCount,
            reachability="REACHABLE" if path.status == PathStatusEnum.POSSIBLE else path.status.value,
            riskScore=risk_score_record.score,
            riskScoreFormatted=f"{risk_score_record.score:.2f} / 100.0",
            riskLevel=risk_score_record.level,
            visualState=vis_state,
            criticalTarget=risk_score_record.criticalTarget,
            explanation=risk_score_record.explanation
        )

    def generate_comprehensive_explanation(
        self,
        path: DiscoveredPathDetail,
        risk: AttackPathRisk,
        ml_threat_features: Optional[List[str]] = None
    ) -> ComprehensivePathExplanationReport:
        chain = path.nodeSequence
        target_id = chain[-1]
        target_node = attack_path_graph.get_node(target_id)
        vis_state = self.determine_visual_state(path.status, risk.level)

        # 1. ML Telemetry Attribution Clause
        if ml_threat_features:
            ml_text = f"The initial threat prediction was influenced by abnormal {', '.join(ml_threat_features[:3])}."
        else:
            ml_text = f"Threat probability was assessed at {risk.factors.entryThreatProbability*100:.1f}% based on baseline telemetry deviations."

        # 2. Contextual Asset Risk Clause
        vuln_names = [v.vulnerabilityId for v in risk.vulnerabilityAssessments if v.relevance.value == "RELEVANT"]
        if vuln_names:
            risk_text = f"The route exposes active vulnerabilities ({', '.join(vuln_names[:2])}) targeting {target_id}."
        else:
            risk_text = f"The destination host {target_id} has {target_node.assetCriticality} asset criticality."

        # 3. Graph Topology Traversal Clause
        if path.status == PathStatusEnum.BLOCKED:
            topo_text = f"The modeled traversal from {chain[0]} toward {target_id} is severed at {path.blockedAt or chain[-1]} ({path.blockingReason})."
            mitigation_text = "Security control actively enforces isolation. Continue audit logging."
        else:
            transit_nodes = ", ".join(chain[1:-1]) if len(chain) > 2 else "direct link"
            topo_text = f"The modeled attack path traverses {transit_nodes} directly reaching crown jewel {target_id}."
            mitigation_text = f"Apply immediate network segmentation between {chain[-2]} and {target_id} on exposed destination port."

        # 4. Synthesized Narrative
        combined = f"{ml_text} {topo_text} {risk_text} Resulting in {risk.level.value} path risk ({risk.score:.1f}/100)."

        report = ComprehensivePathExplanationReport(
            pathId=path.pathId,
            nodeSequence=chain,
            directedChainString=" -> ".join(chain),
            visualState=vis_state,
            pathRiskScore=risk.score,
            pathRiskLevel=risk.level,
            criticalTarget=risk.criticalTarget,
            mlEvidence=ml_text,
            riskEvidence=risk_text,
            graphTopologyEvidence=topo_text,
            combinedExplanation=combined,
            recommendedMitigation=mitigation_text
        )

        self.report_history.append(report)
        self._persist_reports()
        return report

    def filter_graph_nodes(self, filters: GraphVisualizationFilter) -> Dict[str, AttackPathNode]:
        result = {}
        for nid, node in attack_path_graph.nodes.items():
            if filters.zone and node.zone != filters.zone:
                continue
            if filters.deviceType and node.deviceType != filters.deviceType:
                continue
            if filters.hasVulnerabilities is not None:
                has_v = len(node.vulnerabilities) > 0
                if has_v != filters.hasVulnerabilities:
                    continue
            tier = threshold_classifier.classify(node.riskScore)
            if filters.riskLevel and tier != filters.riskLevel:
                continue
            if filters.criticalTargetOnly and node.assetCriticality not in ("HIGH", "CRITICAL"):
                continue
            result[nid] = node
        return result

    def _persist_reports(self):
        data = [r.model_dump() for r in self.report_history[-100:]]
        with open(EXP_REPORTS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def clear(self):
        self.report_history.clear()
        if EXP_REPORTS_FILE.exists():
            try:
                EXP_REPORTS_FILE.unlink()
            except Exception:
                pass

attack_path_visual_engine = AttackPathVisualEngine()