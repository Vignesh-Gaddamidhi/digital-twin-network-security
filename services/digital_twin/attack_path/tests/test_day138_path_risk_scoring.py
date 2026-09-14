import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[4]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.risk.factors.factor_types import RiskLevelTier
from services.digital_twin.attack_path.graph.graph_models import (
    NodeTypeEnum, PathStatusEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.discovery.discovery_models import DiscoveredPathDetail
from services.digital_twin.attack_path.scoring.path_scoring_models import (
    VulnerabilityRelevanceEnum, PathRiskFactors
)
from services.digital_twin.attack_path.scoring.path_risk_engine import path_risk_engine

def run_day138_suite():
    print("=" * 80)
    print("       WEEK 20 - DAY 138: PATH RISK SCORING & PRIORITIZATION AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    path_risk_engine.clear()

    # 1. Vulnerability Relevance Audit
    print("[1/10] Auditing Service-Aware Vulnerability Relevance...")
    rel_sql = path_risk_engine.evaluate_vulnerability_relevance("DB-01", "CVE-2026-SQLI", 3306, "MYSQL")
    rel_web = path_risk_engine.evaluate_vulnerability_relevance("WEB-01", "CVE-2026-WEB-RCE", 443, "HTTPS")
    rel_unrel = path_risk_engine.evaluate_vulnerability_relevance("DB-01", "CVE-2026-UNUSED", 22, "SSH")

    print(f"    SQL on Port 3306 (MySQL) : {rel_sql.relevance.value} (Weight: {rel_sql.effectiveWeight:.2f})")
    print(f"    RCE on Port 443  (HTTPS) : {rel_web.relevance.value} (Weight: {rel_web.effectiveWeight:.2f})")
    print(f"    Unrelated CVE on SSH     : {rel_unrel.relevance.value} (Weight: {rel_unrel.effectiveWeight:.2f})")

    assert rel_sql.relevance == VulnerabilityRelevanceEnum.RELEVANT
    assert rel_sql.effectiveWeight == 1.00
    assert rel_web.relevance == VulnerabilityRelevanceEnum.RELEVANT
    assert rel_unrel.relevance in (VulnerabilityRelevanceEnum.POSSIBLY_RELEVANT, VulnerabilityRelevanceEnum.NOT_RELEVANT)
    print("    [PASS] Vulnerability relevance correctly evaluates active edge service.")

    # 2. Path Risk Calculation (Canonical Path: ATTACKER -> WEB -> DB)
    print("\n[2/10] Auditing Canonical Path Risk Calculation...")
    path_canon = DiscoveredPathDetail(
        nodeSequence=["ATTACKER-EXT", "WEB-01", "DB-01"],
        edgeSequence=["CONN-01", "CONN-03"],
        hopCount=2,
        status=PathStatusEnum.POSSIBLE,
        vulnerabilitiesEncountered=["CVE-2026-WEB-RCE", "CVE-2026-SQLI"]
    )

    risk_canon = path_risk_engine.calculate_path_risk(path_canon, entry_threat_probability=0.87, attack_impact_weight=0.80)
    print(f"    Calculated Path Risk Score : {risk_canon.score:.2f} / 100.0 [{risk_canon.level.value}]")
    print(f"    Critical Target Flagged    : {risk_canon.criticalTarget}")
    print(f"    Max Node Risk in Path      : {risk_canon.factors.maximumNodeRisk:.1f}")
    print(f"    Target Criticality Weight  : {risk_canon.factors.targetCriticality:.2f}")

    assert risk_canon.score > 60.0
    assert risk_canon.level in (RiskLevelTier.HIGH, RiskLevelTier.CRITICAL)
    assert risk_canon.criticalTarget is True
    assert risk_canon.reachabilityMultiplier == 1.00
    print("    [PASS] Path risk formula executes without mathematical collapse.")

    # 3. Target Criticality Divergence (DB-01 vs CLIENT-01 Target)
    print("\n[3/10] Auditing Target Criticality Divergence...")
    path_to_client = DiscoveredPathDetail(
        nodeSequence=["ATTACKER-EXT", "CLIENT-01"],
        edgeSequence=["CONN-01"],
        hopCount=1,
        status=PathStatusEnum.POSSIBLE
    )
    risk_to_client = path_risk_engine.calculate_path_risk(path_to_client, entry_threat_probability=0.87, attack_impact_weight=0.80)
    print(f"    Path to DB-01     (CRITICAL Target) : Risk = {risk_canon.score:.2f} [{risk_canon.level.value}]")
    print(f"    Path to CLIENT-01 (LOW Target)      : Risk = {risk_to_client.score:.2f} [{risk_to_client.level.value}]")

    assert risk_canon.score > risk_to_client.score
    assert risk_to_client.criticalTarget is False
    print("    [PASS] Crown jewel target receives significantly higher priority score.")

    # 4. Blocked Path Risk Handling
    print("\n[4/10] Auditing Blocked Path Penalty and Residual Retention...")
    path_blocked = DiscoveredPathDetail(
        nodeSequence=["CLIENT-01", "DB-01"],
        edgeSequence=["CONN-05"],
        hopCount=1,
        status=PathStatusEnum.BLOCKED,
        blockingReason="FW-RULE-04: Segmentation Block"
    )
    risk_blocked = path_risk_engine.calculate_path_risk(path_blocked, entry_threat_probability=0.87, attack_impact_weight=0.80)
    print(f"    Blocked Path Risk Score : {risk_blocked.score:.2f} (Reachability Multiplier: {risk_blocked.reachabilityMultiplier})")

    assert risk_blocked.reachabilityMultiplier == 0.15
    assert risk_blocked.score < 25.0
    assert risk_blocked.level == RiskLevelTier.LOW
    print("    [PASS] Blocked paths retain low residual score for audit without cluttering triage.")

    # 5. Partially Reachable Path Handling
    print("\n[5/10] Auditing Partially Reachable Path Scoring...")
    path_partial = DiscoveredPathDetail(
        nodeSequence=["ATTACKER-EXT", "WEB-01", "DB-01"],
        edgeSequence=["CONN-01", "CONN-03"],
        hopCount=2,
        status=PathStatusEnum.PARTIALLY_REACHABLE,
        blockedAt="DB-01"
    )
    risk_partial = path_risk_engine.calculate_path_risk(path_partial, entry_threat_probability=0.87, attack_impact_weight=0.80)
    print(f"    Partial Path Risk Score : {risk_partial.score:.2f} (Multiplier: {risk_partial.reachabilityMultiplier})")

    assert risk_partial.reachabilityMultiplier == 0.50
    assert risk_partial.score < risk_canon.score
    assert risk_partial.score > risk_blocked.score
    print("    [PASS] Partially reachable paths scored between fully reachable and blocked.")

    # 6. Path Ranking Engine (Priority Sorting)
    print("\n[6/10] Auditing Multi-Path Ranking & Prioritization...")
    # Inject 3 candidate paths
    path_a = DiscoveredPathDetail(nodeSequence=["ATTACKER-EXT", "WEB-01", "DB-01"], edgeSequence=["C1", "C3"], hopCount=2, status=PathStatusEnum.POSSIBLE)
    path_b = DiscoveredPathDetail(nodeSequence=["CLIENT-01", "WEB-01", "DB-01"], edgeSequence=["C2", "C3"], hopCount=2, status=PathStatusEnum.POSSIBLE)
    path_c = DiscoveredPathDetail(nodeSequence=["CLIENT-01", "DB-01"], edgeSequence=["C5"], hopCount=1, status=PathStatusEnum.BLOCKED)

    ranking_res = path_risk_engine.rank_paths([path_c, path_a, path_b])
    print(f"    Total Ranked Paths : {len(ranking_res.rankedPaths)}")
    for r in ranking_res.rankedPaths:
        print(f"      Rank {r.rank}: {' -> '.join(r.nodeSequence):<32} | Score: {r.riskScore:5.2f} [{r.riskLevel.value}] | Status: {r.status}")

    assert ranking_res.rankedPaths[0].rank == 1
    assert ranking_res.rankedPaths[0].riskScore >= ranking_res.rankedPaths[1].riskScore
    assert ranking_res.rankedPaths[1].riskScore >= ranking_res.rankedPaths[2].riskScore
    assert ranking_res.rankedPaths[-1].status == "BLOCKED"
    print("    [PASS] Paths ranked deterministically in descending risk order.")

    # 7. Critical Asset Identification Verification
    print("\n[7/10] Auditing Critical Asset Identification...")
    assert ranking_res.rankedPaths[0].criticalTarget is True
    print("    [PASS] Critical asset flags propagated to ranked items.")

    # 8. Risk Level Mapping to Standard Bands
    print("\n[8/10] Auditing Risk Level Tier Mapping ([0,25) LOW, [25,50) MED, [50,75) HIGH, [75,100] CRIT)...")
    for r in ranking_res.rankedPaths:
        if r.riskScore >= 75.0:
            assert r.riskLevel == RiskLevelTier.CRITICAL
        elif r.riskScore >= 50.0:
            assert r.riskLevel == RiskLevelTier.HIGH
        elif r.riskScore >= 25.0:
            assert r.riskLevel == RiskLevelTier.MEDIUM
        else:
            assert r.riskLevel == RiskLevelTier.LOW
    print("    [PASS] Risk scores correctly map to Phase 16 operational tiers.")

    # 9. Formatted Summary String Validation
    print("\n[9/10] Auditing Formatted Summary Output...")
    summary = risk_canon.to_formatted_summary()
    print(summary)
    assert "AttackPathRisk" in summary
    assert "Score:" in summary
    assert "Critical Target: True" in summary
    print("    [PASS] Formatted ASCII summary validated.")

    # 10. Disk Artifact Persistence Audit
    print("\n[10/10] Auditing Disk Artifact Persistence...")
    out_file = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path" / "path_risk_scores.json"
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        stored = json.load(f)
    assert len(stored) >= 3
    print(f"    Persisted Risk Scores Count: {len(stored)}")
    print("    [PASS] Path risk scores verified on disk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 138 PATH RISK SCORING TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day138_suite()