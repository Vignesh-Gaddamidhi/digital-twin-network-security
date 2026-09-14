import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[4]
RISK_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path"
SCORES_FILE = RISK_ARTIFACTS_DIR / "path_risk_scores.json"

from services.digital_twin.risk.factors.factor_types import (
    RiskLevelTier, FACTOR_NORMALIZATION_MAP
)
from services.digital_twin.risk.thresholds.threshold_classifier import threshold_classifier
from services.digital_twin.attack_path.graph.graph_models import (
    PathStatusEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.discovery.discovery_models import DiscoveredPathDetail
from services.digital_twin.attack_path.scoring.path_scoring_models import (
    VulnerabilityRelevanceEnum, VulnerabilityRelevanceAssessment, PathRiskFactors,
    AttackPathRisk, RankedPathItem, PathRankingResult
)

class PathRiskEngine:
    """Evaluates composite vulnerability-aware and context-aware risk across attack paths."""

    def __init__(self, artifacts_dir: Path = RISK_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.score_history: List[AttackPathRisk] = []

    def evaluate_vulnerability_relevance(
        self,
        node_id: str,
        vulnerability_id: str,
        traversed_port: Optional[int],
        traversed_service: Optional[str]
    ) -> VulnerabilityRelevanceAssessment:
        vuln_upper = vulnerability_id.upper()
        srv_upper = (traversed_service or "").upper()

        # Check service/port relevance
        if "SQL" in vuln_upper and (traversed_port in (3306, 5432, 1433) or "SQL" in srv_upper):
            rel = VulnerabilityRelevanceEnum.RELEVANT
            weight = 1.00
            note = f"Vulnerability '{vulnerability_id}' directly targets exposed database service ({srv_upper}:{traversed_port})."
        elif "RCE" in vuln_upper and (traversed_port in (80, 443, 8080) or "HTTP" in srv_upper):
            rel = VulnerabilityRelevanceEnum.RELEVANT
            weight = 1.00
            note = f"Vulnerability '{vulnerability_id}' directly targets exposed web application tier ({srv_upper}:{traversed_port})."
        elif "SSH" in vuln_upper and (traversed_port == 22 or "SSH" in srv_upper):
            rel = VulnerabilityRelevanceEnum.RELEVANT
            weight = 0.90
            note = f"Vulnerability '{vulnerability_id}' targets administrative SSH channel."
        elif len(vulnerability_id.strip()) > 0:
            rel = VulnerabilityRelevanceEnum.POSSIBLY_RELEVANT
            weight = 0.50
            note = f"Vulnerability '{vulnerability_id}' active on host, but indirect service correlation."
        else:
            rel = VulnerabilityRelevanceEnum.NOT_RELEVANT
            weight = 0.20
            note = "No active exploitable vulnerability correlation along edge."

        return VulnerabilityRelevanceAssessment(
            vulnerabilityId=vulnerability_id,
            nodeId=node_id,
            relevance=rel,
            traversedPort=traversed_port,
            traversedService=traversed_service,
            affectedService=srv_upper,
            effectiveWeight=weight,
            rationale=note
        )

    def calculate_path_risk(
        self,
        path: DiscoveredPathDetail,
        entry_threat_probability: float = 0.87,
        attack_impact_weight: float = 0.80,
        persist: bool = True
    ) -> AttackPathRisk:
        chain = path.nodeSequence
        target_id = chain[-1]
        target_node = attack_path_graph.get_node(target_id)
        is_critical_target = target_node.assetCriticality in ("HIGH", "CRITICAL")
        tgt_crit_score = FACTOR_NORMALIZATION_MAP.get(target_node.assetCriticality, 0.40)

        # 1. Weakest Link / Maximum Node Risk along the path
        node_risks = []
        for nid in chain:
            nd = attack_path_graph.get_node(nid)
            node_risks.append(nd.riskScore)

        max_node_risk = max(node_risks) if node_risks else 20.0
        norm_max_node_risk = max_node_risk / 100.0

        # 2. Evaluate Vulnerability Relevance across traversed edges
        vuln_assessments: List[VulnerabilityRelevanceAssessment] = []
        vuln_weights = []

        hop_vulns = []
        for i in range(len(chain) - 1):
            u, v = chain[i], chain[i + 1]
            matching = [e for e in attack_path_graph.edges.values() if e.sourceNode == u and e.destinationNode == v]
            if matching:
                edge = matching[0]
                v_node = attack_path_graph.get_node(v)
                curr_hop_weights = []
                for vid in v_node.vulnerabilities:
                    va = self.evaluate_vulnerability_relevance(v, vid, edge.destinationPort, edge.service)
                    vuln_assessments.append(va)
                    curr_hop_weights.append(va.effectiveWeight)
                hop_vulns.append(max(curr_hop_weights) if curr_hop_weights else 0.20)

        cum_vuln = float(sum(hop_vulns) / len(hop_vulns)) if hop_vulns else 0.20

        # 3. Reachability Multiplier
        if path.status == PathStatusEnum.POSSIBLE:
            reach_mult = 1.00
        elif path.status == PathStatusEnum.PARTIALLY_REACHABLE:
            reach_mult = 0.50
        else:
            reach_mult = 0.15  # Blocked paths retain minimal residual tracking score

        # 4. Composite Formula: (0.35 * R_max + 0.25 * C_tgt + 0.20 * V_vuln + 0.20 * I_impact) * reach_mult
        raw_composite = (
            (0.35 * norm_max_node_risk) +
            (0.25 * tgt_crit_score) +
            (0.20 * cum_vuln) +
            (0.20 * attack_impact_weight)
        ) * reach_mult

        final_score = round(raw_composite * 100.0, 2)
        final_score = min(100.0, max(0.0, final_score))
        tier = threshold_classifier.classify(final_score)

        explanation = (
            f"Path risk assessed at {final_score:.2f} [{tier.value}]. "
            f"Maximum intermediate node risk is {max_node_risk:.1f}/100, targeting {target_id} "
            f"({target_node.assetCriticality} criticality) with {cum_vuln:.2f} vulnerability factor. "
            f"Reachability status: {path.status.value} (multiplier: {reach_mult:.2f})."
        )

        factors = PathRiskFactors(
            entryThreatProbability=entry_threat_probability,
            maximumNodeRisk=max_node_risk,
            cumulativeVulnerabilityExposure=cum_vuln,
            targetCriticality=tgt_crit_score,
            attackImpact=attack_impact_weight,
            pathLength=path.hopCount,
            reachableEdges=len([e for e in path.edgeSequence if e in attack_path_graph.edges and attack_path_graph.edges[e].reachable]),
            securityControlStrength=0.80 if path.status == PathStatusEnum.BLOCKED else 0.20
        )

        record = AttackPathRisk(
            pathId=path.pathId,
            nodeSequence=chain,
            score=final_score,
            scoreFormatted=f"{final_score:.2f} / 100.0",
            level=tier,
            factors=factors,
            threatContribution=round(0.35 * norm_max_node_risk * reach_mult * 100, 2),
            vulnerabilityContribution=round(0.20 * cum_vuln * reach_mult * 100, 2),
            assetContribution=round(0.25 * tgt_crit_score * reach_mult * 100, 2),
            impactContribution=round(0.20 * attack_impact_weight * reach_mult * 100, 2),
            reachabilityMultiplier=reach_mult,
            criticalTarget=is_critical_target,
            vulnerabilityAssessments=vuln_assessments,
            explanation=explanation
        )

        self.score_history.append(record)
        if persist:
            self._persist_scores()
        return record

    def rank_paths(
        self,
        paths: List[DiscoveredPathDetail],
        entry_threat_probability: float = 0.87,
        attack_impact_weight: float = 0.80,
        persist: bool = True
    ) -> PathRankingResult:
        scored_items: List[Tuple[AttackPathRisk, DiscoveredPathDetail]] = []

        for p in paths:
            risk_rec = self.calculate_path_risk(p, entry_threat_probability, attack_impact_weight, persist=False)
            scored_items.append((risk_rec, p))

        if persist and scored_items:
            self._persist_scores()

        # Sort descending by risk score
        scored_items.sort(key=lambda x: x[0].score, reverse=True)

        ranked_list: List[RankedPathItem] = []
        for idx, (r, p) in enumerate(scored_items, start=1):
            ranked_list.append(RankedPathItem(
                rank=idx,
                pathId=r.pathId,
                nodeSequence=r.nodeSequence,
                riskScore=r.score,
                riskLevel=r.level,
                status=p.status.value,
                criticalTarget=r.criticalTarget,
                explanation=r.explanation
            ))

        highest_path = ranked_list[0] if ranked_list else None

        return PathRankingResult(
            rankedPaths=ranked_list,
            highestRiskPathId=highest_path.pathId if highest_path else "NONE",
            highestRiskScore=highest_path.riskScore if highest_path else 0.0,
            highestRiskLevel=highest_path.riskLevel if highest_path else RiskLevelTier.LOW
        )

    def _persist_scores(self):
        data = [s.model_dump() for s in self.score_history[-100:]]
        with open(SCORES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def clear(self):
        self.score_history.clear()
        if SCORES_FILE.exists():
            try:
                SCORES_FILE.unlink()
            except Exception:
                pass

path_risk_engine = PathRiskEngine()