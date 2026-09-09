import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[5]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.attack_scenario import (
    AttackScenarioModel, AttackScenarioCategoryEnum, AttackScenarioSeverityEnum,
    ScenarioPrecondition, ScenarioTrafficPattern, ExpectedIndicator, ScenarioRecoveryConfig
)
from packages.shared_types.src.preconditions import PreconditionRuleModel, PreconditionTypeEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.simulation.attack.framework.attack_scenario_runner import attack_scenario_runner

def run_attack_scenario_runner_suite():
    print("=" * 80)
    print("       WEEK 10 - DAY 71: GENERIC ATTACK SCENARIO RUNNER MASTER AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    port_service_engine.clear()
    performance_state_engine.clear()
    network_state_engine.clear()
    attack_scenario_runner.resetScenario()

    # 1. Construct Canonical Attack Scenario
    print("[1/5] Defining Canonical Reconnaissance Scenario (SCN-PORTSCAN-001)...")
    scenario_def = AttackScenarioModel(
        scenarioId="SCN-PORTSCAN-001",
        name="Automated SYN Port Sweep Scenario",
        category=AttackScenarioCategoryEnum.PORT_SCAN,
        description="Scans ports 21, 22, 23, 25, 80, 443, 8080 against target server",
        sourceDevice="client-01",
        targetDevice="web-01",
        severity=AttackScenarioSeverityEnum.MEDIUM,
        durationSeconds=5,
        preconditions=ScenarioPrecondition(
            targetDevice="web-01",
            requiredOpenPorts=[80, 443]
        ),
        preconditionRules=[
            PreconditionRuleModel(type=PreconditionTypeEnum.DEVICE_EXISTS, target="web-01", expectedValue=True),
            PreconditionRuleModel(type=PreconditionTypeEnum.DEVICE_EXISTS, target="client-01", expectedValue=True)
        ],
        trafficPattern=ScenarioTrafficPattern(
            patternType="SEQUENTIAL",
            protocol="TCP",
            parameters={"ports": [21, 22, 23, 25, 80, 443, 8080]}
        ),
        expectedIndicators=[
            ExpectedIndicator(
                indicatorType="UNUSUAL_PORT_ACTIVITY",
                thresholdMetric="unique_destination_ports",
                expectedThreshold=5.0,
                description="Unique destination ports probed > 5"
            )
        ],
        recovery=ScenarioRecoveryConfig(
            autoRecover=True,
            resetSocketConnections=True,
            restoreTraffic=True,
            revertPortMutations=True
        )
    )
    print("    [PASS] Scenario defined with preconditions, pattern, indicators, and recovery.")

    # 2. Precondition Failure Verification (Unprovisioned Target)
    print("\n[2/5] Testing Precondition Failure Interception before execution...")
    attack_scenario_runner.loadScenario(scenario_def)
    valid = attack_scenario_runner.validateScenario()
    assert valid is False
    assert attack_scenario_runner.getScenarioState() == "FAILED"
    print("    [PASS] Precondition engine safely halted runner at state 'FAILED'.")

    # 3. Provision Digital Twin Topology
    print("\n[3/5] Provisioning Topology to Satisfy Preconditions...")
    cli = NetworkDeviceModel(id="client-01", hostname="CLIENT-01", type=DeviceTypeEnum.CLIENT, networkZone=NetworkZoneEnum.INTERNAL)
    web = NetworkDeviceModel(id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER, networkZone=NetworkZoneEnum.DMZ, ports=[80, 443])
    device_registry.createDevice(cli)
    device_registry.createDevice(web)
    port_service_engine.openPort("web-01", 80, service_name="HTTP")
    port_service_engine.openPort("web-01", 443, service_name="HTTPS")
    print("    [PASS] Registered client-01 and web-01 with baseline ports 80 and 443.")

    # 4. Full End-to-End Execution
    print("\n[4/5] Executing Full 12-Step Attack Scenario Pipeline via executeScenario()...")
    attack_scenario_runner.loadScenario(scenario_def)
    result = attack_scenario_runner.executeScenario()

    print(f"    Run ID                 : {result.runId}")
    print(f"    Final Runner State     : {result.finalState}")
    print(f"    Events Emitted         : {result.eventsGenerated}")
    print(f"    Total Payload Bytes    : {result.bytesGenerated}B")
    print(f"    Calculated Risk Score  : {result.riskScore} ({result.riskLevel})")
    print(f"    Indicators Observed    : {result.indicatorsObserved}")
    print(f"    Alerts Generated       : {result.alertsGenerated}")
    print(f"    Recovery Status        : {result.recoveryStatus} (Verified: {result.recoveryVerified})")

    assert result.finalState == "COMPLETED"
    assert result.eventsGenerated == 7
    assert "UNUSUAL_PORT_ACTIVITY" in result.indicatorsObserved
    assert "ALERT-UNUSUAL_PORT_ACTIVITY" in result.alertsGenerated
    assert result.riskScore == 34.0
    assert result.recoveryVerified is True
    print("    [PASS] Complete execution pipeline succeeded with verified indicators and recovery.")

    # 5. Post-Healing Digital Twin Validation & Export Audit
    print("\n[5/5] Auditing Digital Twin Healed Posture & JSON Artifact Export...")
    healed_cpu = performance_state_engine.getPerformanceState("web-01").cpu
    healed_util = network_state_engine.getNetworkMetrics("web-01").networkUtilisation
    assert healed_cpu <= 25.0
    assert healed_util <= 20.0
    print(f"    [PASS] Twin state confirmed restored: CPU={healed_cpu}%, Util={healed_util}%.")

    export_path = attack_scenario_runner.exportScenarioResults()
    assert export_path.exists()
    print(f"    [PASS] ScenarioResult exported cleanly: {export_path.name}")

    print("\n" + "=" * 80)
    print("   ALL DAY 71 ATTACK SCENARIO RUNNER MASTER INTEGRATION TESTS PASSED")
    print("=" * 80)

if __name__ == "__main__":
    run_attack_scenario_runner_suite()