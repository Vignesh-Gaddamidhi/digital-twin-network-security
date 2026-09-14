import json
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[4]
ANALYSIS_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path"
AUDIT_FILE = ANALYSIS_ARTIFACTS_DIR / "master_analysis_audit.json"

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.graph_models import (
    NodeTypeEnum, PathStatusEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.discovery.discovery_models import (
    PathConstraints, DiscoveredPathDetail, PathDiscoveryResult
)
from services.digital_twin.attack_path.discovery.path_discovery_engine import path_discovery_engine
from services.digital_twin.attack_path.scoring.path_scoring_models import (
    AttackPathRisk, RankedPathItem, PathRankingResult
)
from services.digital_twin.attack_path.scoring.path_risk_engine import path_risk_engine
from services.digital_twin.attack_path.visualization.path_visual_engine import attack_path_visual_engine
from services.digital_twin.attack_path.analysis.attack_path_analysis_models import (
    AnalysisStatusEnum, AttackPathAuditRecord, MasterAttackPathAnalysisResult
)

class MasterAttackPathOrchestrator:
    """Master orchestrator connecting Graph, Threat ML, Contextual Risk, Path Discovery, and XAI Explanations."""

    def __init__(self, artifacts_dir: Path = ANALYSIS_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log: List[AttackPathAuditRecord] = []

    def run_master_analysis(
        self,
        source_device_id: str,
        target_device_id: str,
        entry_threat_probability: float = 0.87,
        attack_impact_weight: float = 0.80,
        ml_threat_features: Optional[List[str]] = None,
        constraints: Optional[PathConstraints] = None
    ) -> MasterAttackPathAnalysisResult:
        t0_total = time.perf_counter()
        latencies: Dict[str, float] = {}

        # 1. Defensive Guardrail: Graph Data Check
        if not attack_path_graph.nodes:
            raise ValueError("NO_GRAPH_DATA: Attack path graph contains no nodes.")

        # 2. Defensive Guardrail: Source Node Exists
        t0_src = time.perf_counter()
        try:
            _ = attack_path_graph.get_node(source_device_id)
        except KeyError:
            raise KeyError(f"SOURCE_NOT_FOUND: Source device '{source_device_id}' does not exist in graph.")
        latencies["sourceValidationMs"] = round((time.perf_counter() - t0_src) * 1000, 3)

        # 3. Defensive Guardrail: Target Node Exists
        t0_tgt = time.perf_counter()
        try:
            target_node = attack_path_graph.get_node(target_device_id)
        except KeyError:
            raise KeyError(f"TARGET_NOT_FOUND: Target device '{target_device_id}' does not exist in graph.")
        latencies["targetValidationMs"] = round((time.perf_counter() - t0_tgt) * 1000, 3)

        # 4. Path Discovery (DFS All Bounded with Cycle Prevention)
        t0_disc = time.perf_counter()
        discovery_res = path_discovery_engine.find_all_paths(
            source=source_device_id,
            target=target_device_id,
            constraints=constraints
        )
        latencies["pathDiscoveryMs"] = round((time.perf_counter() - t0_disc) * 1000, 3)

        # 5. Path Risk Scoring & Prioritization
        t0_score = time.perf_counter()
        ranking_res = path_risk_engine.rank_paths(
            paths=discovery_res.paths,
            entry_threat_probability=entry_threat_probability,
            attack_impact_weight=attack_impact_weight
        )
        latencies["pathScoringAndRankingMs"] = round((time.perf_counter() - t0_score) * 1000, 3)

        # 6. Forensic Explanation Synthesis for Top-Ranked Path
        t0_exp = time.perf_counter()
        top_exp = None
        if ranking_res.rankedPaths and discovery_res.paths:
            top_ranked = ranking_res.rankedPaths[0]
            matching_path = next((p for p in discovery_res.paths if p.pathId == top_ranked.pathId), discovery_res.paths[0])
            top_risk = path_risk_engine.calculate_path_risk(matching_path, entry_threat_probability, attack_impact_weight)
            top_exp = attack_path_visual_engine.generate_comprehensive_explanation(
                path=matching_path,
                risk=top_risk,
                ml_threat_features=ml_threat_features or ["connection frequency", "destination diversity", "port activity"]
            )
        latencies["explanationSynthesisMs"] = round((time.perf_counter() - t0_exp) * 1000, 3)

        # 7. Construct Audit Record
        is_crit = target_node.assetCriticality in ("HIGH", "CRITICAL")
        analysis_id = f"APANA-{uuid.uuid4().hex[:8].upper()}"

        audit_rec = AttackPathAuditRecord(
            analysisId=analysis_id,
            source=source_device_id,
            target=target_device_id,
            traversalMethod="DFS_ALL_BOUNDED",
            pathsDiscovered=discovery_res.pathsFound,
            pathsBlocked=discovery_res.pathsBlocked,
            pathsPartial=discovery_res.pathsPartial,
            selectedPath=ranking_res.rankedPaths[0].nodeSequence if ranking_res.rankedPaths else None,
            pathRiskScore=ranking_res.highestRiskScore,
            pathRiskLevel=ranking_res.highestRiskLevel,
            criticalTarget=is_crit,
            explanationId=top_exp.reportId if top_exp else None,
            status=AnalysisStatusEnum.COMPLETED if discovery_res.pathsFound > 0 else AnalysisStatusEnum.NO_PATH_FOUND
        )

        latencies["totalMasterAnalysisLatencyMs"] = round((time.perf_counter() - t0_total) * 1000, 2)

        master_result = MasterAttackPathAnalysisResult(
            analysisId=analysis_id,
            source=source_device_id,
            target=target_device_id,
            rankedPaths=ranking_res.rankedPaths,
            topPathExplanation=top_exp,
            auditRecord=audit_rec,
            executionLatencyMs=latencies
        )

        self.audit_log.append(audit_rec)
        self._persist_audit_record(audit_rec)
        return master_result

    def benchmark_graph_scalability(self, node_counts: List[int] = [10, 25, 50, 100]) -> List[Dict[str, Any]]:
        results = []
        for n_count in node_counts:
            # Construct synthetic dense tree topology
            t0 = time.perf_counter()
            attack_path_graph.clear()

            # Seed nodes
            for i in range(n_count):
                nid = f"NODE-{i:03d}"
                zone = "DATABASE" if i == n_count - 1 else ("DMZ" if i < 5 else "INTERNAL")
                crit = "CRITICAL" if i == n_count - 1 else "MEDIUM"
                attack_path_graph.add_node(AttackPathNode(
                    nodeId=nid, deviceId=nid, hostname=f"{nid.lower()}.synth.internal", zone=zone, assetCriticality=crit, reachable=True
                ))

            # Seed directed chain + alternate edges
            for i in range(n_count - 1):
                src = f"NODE-{i:03d}"
                dst = f"NODE-{i+1:03d}"
                attack_path_graph.add_edge(AttackPathEdge(
                    edgeId=f"EDGE-{i}-{i+1}", sourceNode=src, destinationNode=dst, reachable=True
                ))
                if i + 2 < n_count:
                    attack_path_graph.add_edge(AttackPathEdge(
                        edgeId=f"EDGE-{i}-{i+2}", sourceNode=src, destinationNode=f"NODE-{i+2:03d}", reachable=True
                    ))

            build_time = round((time.perf_counter() - t0) * 1000, 3)

            # Measure path discovery & scoring (in-memory algorithmic benchmark)
            t1 = time.perf_counter()
            disc = path_discovery_engine.find_all_paths("NODE-000", f"NODE-{n_count-1:03d}", PathConstraints(maxDepth=5, maxPaths=15), persist=False)
            disc_time = round((time.perf_counter() - t1) * 1000, 3)

            t2 = time.perf_counter()
            _ = path_risk_engine.rank_paths(disc.paths, persist=False)
            rank_time = round((time.perf_counter() - t2) * 1000, 3)

            results.append({
                "nodes": n_count,
                "edges": len(attack_path_graph.edges),
                "graphConstructionMs": build_time,
                "pathDiscoveryMs": disc_time,
                "pathRankingMs": rank_time,
                "totalExecutionMs": round(build_time + disc_time + rank_time, 3),
                "pathsDiscovered": disc.pathsFound
            })

        # Restore canonical topology
        twin_graph_synchronizer._seed_default_twin_state()
        twin_graph_synchronizer.full_synchronization()
        return results

    def _persist_audit_record(self, record: AttackPathAuditRecord):
        existing = []
        if AUDIT_FILE.exists():
            try:
                with open(AUDIT_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        existing.append(record.model_dump())
        existing = existing[-100:]
        with open(AUDIT_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def clear(self):
        self.audit_log.clear()
        if AUDIT_FILE.exists():
            try:
                AUDIT_FILE.unlink()
            except Exception:
                pass

master_attack_path_orchestrator = MasterAttackPathOrchestrator()