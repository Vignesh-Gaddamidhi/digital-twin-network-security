from typing import Dict, List, Optional, Set
from datetime import datetime, timezone

from packages.shared_types.src.security_state import (
    SecurityPostureStatusEnum, VulnerabilityLifecycleStatusEnum,
    VulnerabilitySeverityEnum, DynamicVulnerabilityEntity,
    DeviceVulnerabilitySummary, SecurityStateTransitionRecord,
    VulnerabilityTransitionRecord
)
from services.digital_twin.core.devices.network_device_registry import device_registry, DeviceNotFoundError

class InvalidSecurityTransitionError(ValueError):
    pass

class InvalidVulnerabilityTransitionError(ValueError):
    pass

class VulnerabilityNotFoundError(KeyError):
    pass

class SecurityStateEngine:
    """Manages dynamic device security postures, vulnerability lifecycles, and risk exposure."""

    # Security State Transition FSM
    VALID_SECURITY_TRANSITIONS: Dict[SecurityPostureStatusEnum, Set[SecurityPostureStatusEnum]] = {
        SecurityPostureStatusEnum.NORMAL: {
            SecurityPostureStatusEnum.MONITORED,
            SecurityPostureStatusEnum.SUSPICIOUS,
            SecurityPostureStatusEnum.AT_RISK,
            SecurityPostureStatusEnum.ISOLATED
        },
        SecurityPostureStatusEnum.MONITORED: {
            SecurityPostureStatusEnum.NORMAL,
            SecurityPostureStatusEnum.SUSPICIOUS,
            SecurityPostureStatusEnum.AT_RISK,
            SecurityPostureStatusEnum.ISOLATED
        },
        SecurityPostureStatusEnum.SUSPICIOUS: {
            SecurityPostureStatusEnum.NORMAL,
            SecurityPostureStatusEnum.MONITORED,
            SecurityPostureStatusEnum.AT_RISK,
            SecurityPostureStatusEnum.COMPROMISED,
            SecurityPostureStatusEnum.ISOLATED
        },
        SecurityPostureStatusEnum.AT_RISK: {
            SecurityPostureStatusEnum.NORMAL,
            SecurityPostureStatusEnum.SUSPICIOUS,
            SecurityPostureStatusEnum.COMPROMISED,
            SecurityPostureStatusEnum.ISOLATED
        },
        SecurityPostureStatusEnum.COMPROMISED: {
            SecurityPostureStatusEnum.ISOLATED,
            SecurityPostureStatusEnum.AT_RISK,  # Remediating
            SecurityPostureStatusEnum.NORMAL    # Fully re-imaged
        },
        SecurityPostureStatusEnum.ISOLATED: {
            SecurityPostureStatusEnum.NORMAL,
            SecurityPostureStatusEnum.MONITORED,
            SecurityPostureStatusEnum.UNKNOWN
        },
        SecurityPostureStatusEnum.UNKNOWN: {
            SecurityPostureStatusEnum.NORMAL,
            SecurityPostureStatusEnum.MONITORED,
            SecurityPostureStatusEnum.ISOLATED
        }
    }

    # Vulnerability Lifecycle Transition FSM
    VALID_VULN_TRANSITIONS: Dict[VulnerabilityLifecycleStatusEnum, Set[VulnerabilityLifecycleStatusEnum]] = {
        VulnerabilityLifecycleStatusEnum.OPEN: {
            VulnerabilityLifecycleStatusEnum.MITIGATED,
            VulnerabilityLifecycleStatusEnum.PATCHED,
            VulnerabilityLifecycleStatusEnum.ACCEPTED
        },
        VulnerabilityLifecycleStatusEnum.MITIGATED: {
            VulnerabilityLifecycleStatusEnum.OPEN,      # Mitigation bypass
            VulnerabilityLifecycleStatusEnum.PATCHED,
            VulnerabilityLifecycleStatusEnum.ACCEPTED
        },
        VulnerabilityLifecycleStatusEnum.ACCEPTED: {
            VulnerabilityLifecycleStatusEnum.OPEN,      # Re-evaluated policy
            VulnerabilityLifecycleStatusEnum.PATCHED,
            VulnerabilityLifecycleStatusEnum.MITIGATED
        },
        VulnerabilityLifecycleStatusEnum.PATCHED: {
            VulnerabilityLifecycleStatusEnum.OPEN       # Regression / failed patch
        },
        VulnerabilityLifecycleStatusEnum.UNKNOWN: {
            VulnerabilityLifecycleStatusEnum.OPEN,
            VulnerabilityLifecycleStatusEnum.PATCHED
        }
    }

    def __init__(self):
        # device_id -> SecurityPostureStatusEnum
        self._device_security_status: Dict[str, SecurityPostureStatusEnum] = {}
        # device_id -> { vuln_id: DynamicVulnerabilityEntity }
        self._device_vulnerabilities: Dict[str, Dict[str, DynamicVulnerabilityEntity]] = {}
        # Audit history ledgers
        self._security_history: List[SecurityStateTransitionRecord] = []
        self._vuln_history: List[VulnerabilityTransitionRecord] = []

    def _ensure_device_registered(self, device_id: str):
        dev = device_registry.getDevice(device_id)
        if not dev:
            raise DeviceNotFoundError(f"Device '{device_id}' not found in Device Registry.")

    # --- 1. SECURITY POSTURE FSM ---
    def getSecurityStatus(self, device_id: str) -> SecurityPostureStatusEnum:
        self._ensure_device_registered(device_id)
        if device_id not in self._device_security_status:
            dev = device_registry.getDevice(device_id)
            curr = getattr(dev, "securityState", "NORMAL")
            try:
                self._device_security_status[device_id] = SecurityPostureStatusEnum(curr)
            except ValueError:
                self._device_security_status[device_id] = SecurityPostureStatusEnum.NORMAL
        return self._device_security_status[device_id]

    def canTransitionSecurityStatus(self, device_id: str, target_status: SecurityPostureStatusEnum) -> bool:
        current = self.getSecurityStatus(device_id)
        if current == target_status:
            return True
        allowed = self.VALID_SECURITY_TRANSITIONS.get(current, set())
        return target_status in allowed

    def transitionSecurityStatus(
        self,
        device_id: str,
        new_status: SecurityPostureStatusEnum,
        reason: str,
        source: str = "ANOMALY_DETECTOR"
    ) -> SecurityStateTransitionRecord:
        self._ensure_device_registered(device_id)
        current = self.getSecurityStatus(device_id)

        if not self.canTransitionSecurityStatus(device_id, new_status):
            raise InvalidSecurityTransitionError(
                f"Illegal security posture transition for device '{device_id}': cannot move from '{current.value}' to '{new_status.value}'."
            )

        self._device_security_status[device_id] = new_status

        # Synchronize root device
        dev = device_registry.getDevice(device_id)
        if dev:
            dev.securityState = new_status.value
            device_registry.updateDevice(dev)

        record = SecurityStateTransitionRecord(
            deviceId=device_id,
            previousStatus=current,
            newStatus=new_status,
            reason=reason,
            source=source,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        self._security_history.append(record)
        return record

    # --- 2. VULNERABILITY LIFECYCLE MANAGEMENT ---
    def addVulnerability(self, device_id: str, vuln: DynamicVulnerabilityEntity) -> DynamicVulnerabilityEntity:
        self._ensure_device_registered(device_id)
        if device_id not in self._device_vulnerabilities:
            self._device_vulnerabilities[device_id] = {}

        self._device_vulnerabilities[device_id][vuln.id] = vuln
        self._sync_vulnerability_risk(device_id)
        return vuln

    def canTransitionVulnerabilityStatus(self, current: VulnerabilityLifecycleStatusEnum, target: VulnerabilityLifecycleStatusEnum) -> bool:
        if current == target:
            return True
        allowed = self.VALID_VULN_TRANSITIONS.get(current, set())
        return target in allowed

    def transitionVulnerabilityStatus(
        self,
        device_id: str,
        vulnerability_id: str,
        new_status: VulnerabilityLifecycleStatusEnum,
        reason: str,
        source: str = "PATCH_MANAGER"
    ) -> VulnerabilityTransitionRecord:
        self._ensure_device_registered(device_id)
        vulns_dict = self._device_vulnerabilities.get(device_id, {})
        if vulnerability_id not in vulns_dict:
            raise VulnerabilityNotFoundError(f"Vulnerability '{vulnerability_id}' not found on device '{device_id}'.")

        vuln = vulns_dict[vulnerability_id]
        current_status = vuln.status

        if not self.canTransitionVulnerabilityStatus(current_status, new_status):
            raise InvalidVulnerabilityTransitionError(
                f"Illegal vulnerability lifecycle transition for '{vulnerability_id}': cannot move from '{current_status.value}' to '{new_status.value}'."
            )

        vuln.status = new_status
        vuln.lastUpdated = datetime.now(timezone.utc).isoformat()

        record = VulnerabilityTransitionRecord(
            deviceId=device_id,
            vulnerabilityId=vulnerability_id,
            previousStatus=current_status,
            newStatus=new_status,
            reason=reason,
            source=source,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        self._vuln_history.append(record)
        self._sync_vulnerability_risk(device_id)
        return record

    def getVulnerabilitySummary(self, device_id: str) -> DeviceVulnerabilitySummary:
        self._ensure_device_registered(device_id)
        vulns = list(self._device_vulnerabilities.get(device_id, {}).values())
        open_vulns = [v for v in vulns if v.status == VulnerabilityLifecycleStatusEnum.OPEN]

        critical_cnt = sum(1 for v in open_vulns if v.severity == VulnerabilitySeverityEnum.CRITICAL or v.cvssScore >= 9.0)
        high_cnt = sum(1 for v in open_vulns if v.severity == VulnerabilitySeverityEnum.HIGH or (7.0 <= v.cvssScore < 9.0))
        medium_cnt = sum(1 for v in open_vulns if v.severity == VulnerabilitySeverityEnum.MEDIUM or (4.0 <= v.cvssScore < 7.0))
        low_cnt = sum(1 for v in open_vulns if v.severity == VulnerabilitySeverityEnum.LOW or (0.1 <= v.cvssScore < 4.0))

        return DeviceVulnerabilitySummary(
            deviceId=device_id,
            totalOpen=len(open_vulns),
            critical=critical_cnt,
            high=high_cnt,
            medium=medium_cnt,
            low=low_cnt,
            vulnerabilities=vulns
        )

    def _sync_vulnerability_risk(self, device_id: str):
        """Calculates dynamic risk score based on open vulnerability exposures."""
        summary = self.getVulnerabilitySummary(device_id)
        dev = device_registry.getDevice(device_id)
        if not dev:
            return

        # Weighted risk index
        score = (summary.critical * 25.0) + (summary.high * 15.0) + (summary.medium * 5.0) + (summary.low * 1.0)
        dev.riskScore = min(round(score, 2), 100.0)

        # Update root device vulnerability ID references
        dev.vulnerabilities = [v.id for v in summary.vulnerabilities if v.status == VulnerabilityLifecycleStatusEnum.OPEN]
        device_registry.updateDevice(dev)

    def getSecurityHistory(self, device_id: Optional[str] = None) -> List[SecurityStateTransitionRecord]:
        if device_id:
            self._ensure_device_registered(device_id)
            return [h for h in self._security_history if h.deviceId == device_id]
        return list(self._security_history)

    def getVulnerabilityHistory(self, device_id: Optional[str] = None) -> List[VulnerabilityTransitionRecord]:
        if device_id:
            self._ensure_device_registered(device_id)
            return [h for h in self._vuln_history if h.deviceId == device_id]
        return list(self._vuln_history)

    def clear(self):
        self._device_security_status.clear()
        self._device_vulnerabilities.clear()
        self._security_history.clear()
        self._vuln_history.clear()

security_state_engine = SecurityStateEngine()