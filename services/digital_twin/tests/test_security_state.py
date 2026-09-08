import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum
from packages.shared_types.src.security_state import (
    SecurityPostureStatusEnum, VulnerabilityLifecycleStatusEnum,
    VulnerabilitySeverityEnum, DynamicVulnerabilityEntity
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError
from services.digital_twin.core.state.security_state_engine import (
    security_state_engine, InvalidSecurityTransitionError,
    InvalidVulnerabilityTransitionError, VulnerabilityNotFoundError
)

def run_security_state_suite():
    print("=" * 80)
    print("       WEEK 7 - DAY 48: SECURITY & VULNERABILITY STATE ENGINE AUDIT")
    print("=" * 80 + "\n")

    device_registry.clear()
    security_state_engine.clear()

    # 1. Provision Canonical Device (WEB-01)
    print("[1/5] Provisioning Base Device (WEB-01) in Registry...")
    web = NetworkDeviceModel(
        id="web-01", hostname="WEB-01", type=DeviceTypeEnum.SERVER,
        networkZone=NetworkZoneEnum.DMZ, currentState="ACTIVE", securityState="NORMAL"
    )
    device_registry.createDevice(web)
    assert security_state_engine.getSecurityStatus("web-01") == SecurityPostureStatusEnum.NORMAL
    print("    [PASS] Provisioned WEB-01 with initial status NORMAL and operational ACTIVE.")

    # 2. Sequential Security Posture Transitions
    print("\n[2/5] Testing Security State Transitions (NORMAL -> SUSPICIOUS -> AT_RISK -> COMPROMISED -> ISOLATED)...")
    
    # NORMAL -> SUSPICIOUS
    rec1 = security_state_engine.transitionSecurityStatus(
        "web-01", SecurityPostureStatusEnum.SUSPICIOUS,
        reason="Anomalous traffic spike on port 443", source="ANOMALY_DETECTOR"
    )
    assert rec1.previousStatus == SecurityPostureStatusEnum.NORMAL
    assert rec1.newStatus == SecurityPostureStatusEnum.SUSPICIOUS
    print(f"    [PASS] NORMAL -> SUSPICIOUS: Reason: '{rec1.reason}'")

    # SUSPICIOUS -> AT_RISK
    rec2 = security_state_engine.transitionSecurityStatus(
        "web-01", SecurityPostureStatusEnum.AT_RISK,
        reason="Targeted reconnaissance against unpatched OpenSSL library", source="THREAT_INTEL"
    )
    assert rec2.newStatus == SecurityPostureStatusEnum.AT_RISK
    print(f"    [PASS] SUSPICIOUS -> AT_RISK: Reason: '{rec2.reason}'")

    # AT_RISK -> COMPROMISED
    rec3 = security_state_engine.transitionSecurityStatus(
        "web-01", SecurityPostureStatusEnum.COMPROMISED,
        reason="Reverse shell spawned by user www-data", source="EDR_SENSOR"
    )
    assert rec3.newStatus == SecurityPostureStatusEnum.COMPROMISED
    print(f"    [PASS] AT_RISK -> COMPROMISED: Reason: '{rec3.reason}'")

    # COMPROMISED -> ISOLATED
    rec4 = security_state_engine.transitionSecurityStatus(
        "web-01", SecurityPostureStatusEnum.ISOLATED,
        reason="Automated incident response quarantine", source="SOAR_PLAYBOOK"
    )
    assert rec4.newStatus == SecurityPostureStatusEnum.ISOLATED
    print(f"    [PASS] COMPROMISED -> ISOLATED: Reason: '{rec4.reason}'")

    # 3. Vulnerability Lifecycle Transitions
    print("\n[3/5] Testing Vulnerability Lifecycle: OPEN -> MITIGATED -> PATCHED...")
    vuln = DynamicVulnerabilityEntity(
        id="VULN-001",
        name="OpenSSH PKCS#11 Provider RCE",
        severity=VulnerabilitySeverityEnum.HIGH,
        cvssScore=8.1,
        affectedService="openssh",
        status=VulnerabilityLifecycleStatusEnum.OPEN
    )
    security_state_engine.addVulnerability("web-01", vuln)

    # OPEN -> MITIGATED
    v_rec1 = security_state_engine.transitionVulnerabilityStatus(
        "web-01", "VULN-001", VulnerabilityLifecycleStatusEnum.MITIGATED,
        reason="Applied iptables rule restricting port 22 access", source="SECOPS"
    )
    assert v_rec1.newStatus == VulnerabilityLifecycleStatusEnum.MITIGATED
    print("    [PASS] VULN-001: OPEN -> MITIGATED")

    # MITIGATED -> PATCHED
    v_rec2 = security_state_engine.transitionVulnerabilityStatus(
        "web-01", "VULN-001", VulnerabilityLifecycleStatusEnum.PATCHED,
        reason="Upgraded OpenSSH package to patched release 9.3p2", source="PATCH_MANAGER"
    )
    assert v_rec2.newStatus == VulnerabilityLifecycleStatusEnum.PATCHED
    print("    [PASS] VULN-001: MITIGATED -> PATCHED")

    # 4. Severity Count Aggregation Test (Critical=0, High=2, Medium=3, Low=1)
    print("\n[4/5] Testing Device Vulnerability Severity Aggregations...")
    # Add High (2), Medium (3), Low (1)
    test_vulns = [
        DynamicVulnerabilityEntity(id="V-H1", name="High Flaw 1", severity=VulnerabilitySeverityEnum.HIGH, cvssScore=8.0, affectedService="web"),
        DynamicVulnerabilityEntity(id="V-H2", name="High Flaw 2", severity=VulnerabilitySeverityEnum.HIGH, cvssScore=7.5, affectedService="web"),
        DynamicVulnerabilityEntity(id="V-M1", name="Med Flaw 1", severity=VulnerabilitySeverityEnum.MEDIUM, cvssScore=5.5, affectedService="web"),
        DynamicVulnerabilityEntity(id="V-M2", name="Med Flaw 2", severity=VulnerabilitySeverityEnum.MEDIUM, cvssScore=5.0, affectedService="web"),
        DynamicVulnerabilityEntity(id="V-M3", name="Med Flaw 3", severity=VulnerabilitySeverityEnum.MEDIUM, cvssScore=4.5, affectedService="web"),
        DynamicVulnerabilityEntity(id="V-L1", name="Low Flaw 1", severity=VulnerabilitySeverityEnum.LOW, cvssScore=2.0, affectedService="web"),
    ]
    for v in test_vulns:
        security_state_engine.addVulnerability("web-01", v)

    summary = security_state_engine.getVulnerabilitySummary("web-01")
    print(f"    Vulnerability Summary for WEB-01: Critical={summary.critical}, High={summary.high}, Medium={summary.medium}, Low={summary.low}, TotalOpen={summary.totalOpen}")
    assert summary.critical == 0
    assert summary.high == 2
    assert summary.medium == 3
    assert summary.low == 1
    assert summary.totalOpen == 6
    print("    [PASS] Summary exact matches: Critical=0, High=2, Medium=3, Low=1.")

    # 5. Invalid Transition Rejection & Boundary Checks
    print("\n[5/5] Testing Rejection of Invalid Security & Vulnerability Transitions...")

    # Illegal security transition: NORMAL cannot jump directly to COMPROMISED
    web2 = NetworkDeviceModel(id="web-02", hostname="WEB-02", type=DeviceTypeEnum.SERVER, securityState="NORMAL")
    device_registry.createDevice(web2)
    try:
        security_state_engine.transitionSecurityStatus(
            "web-02", SecurityPostureStatusEnum.COMPROMISED, reason="Bypass test"
        )
        assert False, "Failed to reject illegal transition!"
    except InvalidSecurityTransitionError as e:
        print(f"    [PASS] Safely rejected NORMAL -> COMPROMISED: {e}")

    # Illegal vulnerability transition: PATCHED cannot transition directly to MITIGATED
    try:
        security_state_engine.transitionVulnerabilityStatus(
            "web-01", "VULN-001", VulnerabilityLifecycleStatusEnum.MITIGATED, reason="Illegal move"
        )
        assert False, "Failed to reject invalid vuln transition!"
    except InvalidVulnerabilityTransitionError as e:
        print(f"    [PASS] Safely rejected PATCHED -> MITIGATED: {e}")

    # Unknown device
    try:
        security_state_engine.getSecurityStatus("ghost-device")
        assert False
    except DeviceNotFoundError:
        print("    [PASS] Safely rejected unknown device query.")

    # Audit trail validation
    sec_history = security_state_engine.getSecurityHistory("web-01")
    vuln_history = security_state_engine.getVulnerabilityHistory("web-01")
    assert len(sec_history) == 4
    assert len(vuln_history) == 2
    print(f"\n[*] Audit Trail: Recorded {len(sec_history)} security transitions and {len(vuln_history)} vulnerability transitions.")

    print("\n" + "=" * 80)
    print("       ALL DAY 48 SECURITY & VULNERABILITY STATE TESTS PASSED CLEANLY")
    print("=" * 80)

if __name__ == "__main__":
    run_security_state_suite()