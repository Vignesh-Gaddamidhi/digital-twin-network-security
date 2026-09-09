import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.attack_scenario import (
    AttackScenarioModel, AttackScenarioCategoryEnum, AttackScenarioSeverityEnum,
    ScenarioPrecondition, ScenarioTrafficPattern
)
from packages.shared_types.src.attack_severity import (
    SeverityLevelEnum, RiskLevelEnum, AssetCriticalityEnum
)
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.simulation.attack.framework.severity_engine import severity_engine

def run_severity_suite():
    print("=" * 80)
    print("       WEEK 10 - DAY 69: SEVERITY & SCENARIO CLASSIFICATION AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()

    # 1. Provision Canonical Devices
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    db = NetworkDeviceModel(id="db-01", hostname="DB-01", type=DeviceTypeEnum.DATABASE, networkZone=NetworkZoneEnum.INTERNAL, ports=[5432])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    device_registry.createDevice(db)

    # 2. Audit All 7 Baseline Scenario Severities
    print("[1/4] Auditing 7 Canonical Scenario Initial Severities...")
    expected_matrix = {
        AttackScenarioCategoryEnum.PORT_SCAN: SeverityLevelEnum.MEDIUM,
        AttackScenarioCategoryEnum.BRUTE_FORCE: SeverityLevelEnum.HIGH,
        AttackScenarioCategoryEnum.DOS: SeverityLevelEnum.HIGH,
        AttackScenarioCategoryEnum.SUSPICIOUS_DNS: SeverityLevelEnum.MEDIUM,
        AttackScenarioCategoryEnum.BEACONING: SeverityLevelEnum.HIGH,
        AttackScenarioCategoryEnum.LATERAL_MOVEMENT: SeverityLevelEnum.HIGH,
        AttackScenarioCategoryEnum.DATA_EXFILTRATION: SeverityLevelEnum.CRITICAL,
    }

    for cat, expected_sev in expected_matrix.items():
        dummy_scen = AttackScenarioModel(
            scenarioId=f"SCN-{cat.name}-001",
            name=f"Test-{cat.name}",
            category=cat,
            description="Audit",
            sourceDevice="client-01",
            targetDevice="web-01",
            preconditions=ScenarioPrecondition(targetDevice="web-01"),
            trafficPattern=ScenarioTrafficPattern(patternType="BURST")
        )
        classification = severity_engine.classify_scenario(dummy_scen)
        print(f"    Scenario Category: {cat.value:<18} -> Initial Severity: {classification.initialSeverity.value}")
        assert classification.initialSeverity == expected_sev

    print("    [PASS] All 7 scenario categories adhere to the canonical baseline severity matrix.")

    # 3. Audit Asset Criticality Assignment
    print("\n[2/4] Auditing Asset Criticality Detection...")
    crit_cli = severity_engine.get_asset_criticality("client-01")
    crit_web = severity_engine.get_asset_criticality("web-01")
    crit_db = severity_engine.get_asset_criticality("db-01")

    print(f"    client-01 -> {crit_cli.value}")
    print(f"    web-01    -> {crit_web.value}")
    print(f"    db-01     -> {crit_db.value}")

    assert crit_cli == AssetCriticalityEnum.MEDIUM
    assert crit_web == AssetCriticalityEnum.HIGH
    assert crit_db == AssetCriticalityEnum.CRITICAL
    print("    [PASS] Target device types accurately mapped to asset criticality levels.")

    # 4. Audit Risk Score Engine (Port Scan against web-01)
    print("\n[3/4] Auditing Risk Score Calculation (Likelihood x Impact) for SCN-PORTSCAN-001...")
    port_scan = AttackScenarioModel(
        scenarioId="SCN-PORTSCAN-001",
        name="TCP Port Scan",
        category=AttackScenarioCategoryEnum.PORT_SCAN,
        description="Reconnaissance scan",
        sourceDevice="client-01",
        targetDevice="web-01",
        preconditions=ScenarioPrecondition(targetDevice="web-01"),
        trafficPattern=ScenarioTrafficPattern(patternType="SWEEP", intensityMultiplier=1.0)
    )
    risk_ps = severity_engine.assess_risk(port_scan)
    print(f"    Likelihood : {risk_ps.likelihoodScore}")
    print(f"    Impact     : {risk_ps.impactScore}")
    print(f"    Risk Score : {risk_ps.riskScore} -> Level: {risk_ps.riskLevel.value}")
    
    assert risk_ps.baseSeverity == SeverityLevelEnum.MEDIUM
    assert risk_ps.riskScore == round(risk_ps.likelihoodScore * risk_ps.impactScore * 10, 2)
    print("    [PASS] Risk score formula (Likelihood x Impact * 10) verified.")

    # 5. Audit Critical Exfiltration Scenario against DB-01
    print("\n[4/4] Auditing Critical Data Exfiltration against DB-01...")
    exfil = AttackScenarioModel(
        scenarioId="SCN-EXFIL-001",
        name="SQL Database Dump Exfiltration",
        category=AttackScenarioCategoryEnum.DATA_EXFILTRATION,
        description="Exfiltrating sensitive customer records",
        sourceDevice="client-01",
        targetDevice="db-01",
        preconditions=ScenarioPrecondition(targetDevice="db-01"),
        trafficPattern=ScenarioTrafficPattern(patternType="BURST", intensityMultiplier=3.0)
    )
    risk_exfil = severity_engine.assess_risk(exfil)
    print(f"    Target Asset Criticality : CRITICAL")
    print(f"    Aggravating Factors      : {risk_exfil.aggravatingFactors}")
    print(f"    Risk Score               : {risk_exfil.riskScore} -> Level: {risk_exfil.riskLevel.value}")

    assert risk_exfil.baseSeverity == SeverityLevelEnum.CRITICAL
    assert risk_exfil.riskLevel == RiskLevelEnum.CRITICAL
    assert risk_exfil.riskScore >= 50.0
    print("    [PASS] High-impact exfiltration against DB correctly assessed as CRITICAL risk.")

    print("\n" + "=" * 80)
    print("       ALL DAY 69 SEVERITY & RISK CLASSIFICATION TESTS PASSED")
    print("=" * 80)

if __name__ == "__main__":
    run_severity_suite()