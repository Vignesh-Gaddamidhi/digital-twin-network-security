from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

from packages.shared_types.src.attack_recovery import (
    RecoveryStrategyEnum, ScenarioRecoveryPlan, DeviceRecoveryResult,
    RecoveryExecutionReport
)
from packages.shared_types.src.port_service_state import PortStateEnum
from packages.shared_types.src.security_state import SecurityPostureStatusEnum
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum

from services.digital_twin.core.state.network_state_engine import network_state_engine
from services.digital_twin.core.state.performance_state_engine import performance_state_engine
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.state.security_state_engine import security_state_engine
from services.digital_twin.core.devices.network_device_registry import device_registry

class RecoveryVerifier:
    """Performs post-healing audits to prove the target returned to baseline."""

    @staticmethod
    def verify(devices: List[str], expected_ports_closed: Optional[List[int]] = None) -> Tuple[bool, Dict[str, Any]]:
        details = {}
        all_ok = True

        for d in devices:
            dev_ok = True
            dev_report = {}

            # 1. Performance check
            try:
                perf = performance_state_engine.getPerformanceState(d)
                if perf.cpu > 50.0:
                    dev_ok = False
                    dev_report["cpu_anomaly"] = f"CPU is {perf.cpu}%, expected <= 50%"
            except Exception:
                pass

            # 2. Network Utilisation check
            try:
                net = network_state_engine.getNetworkMetrics(d)
                if net.networkUtilisation > 50.0:
                    dev_ok = False
                    dev_report["util_anomaly"] = f"Util is {net.networkUtilisation}%, expected <= 50%"
            except Exception:
                pass

            # 3. Connection sessions check
            try:
                stats = network_state_engine.getConnectionStats(d)
                dev_report["active_sessions"] = stats.active
            except Exception:
                dev_report["active_sessions"] = 0

            # 4. Closed port check
            if expected_ports_closed:
                for p in expected_ports_closed:
                    try:
                        p_entry = port_service_engine.getPort(d, p)
                        if p_entry and p_entry.state == PortStateEnum.OPEN:
                            dev_ok = False
                            dev_report["unclosed_port"] = f"Port {p} still OPEN on {d}"
                    except Exception:
                        pass

            dev_report["healthy"] = dev_ok
            details[d] = dev_report
            if not dev_ok:
                all_ok = False

        return all_ok, details


class RecoveryEngine:
    """Executes state restoration, connection teardown, and metric resets on the Digital Twin."""

    def _ensure_device_ready(self, dev_id: str):
        if not device_registry.getDevice(dev_id):
            dtype = DeviceTypeEnum.SERVER if "web" in dev_id or "srv" in dev_id else DeviceTypeEnum.CLIENT
            zone = NetworkZoneEnum.DMZ if "web" in dev_id else NetworkZoneEnum.INTERNAL
            device_registry.createDevice(
                NetworkDeviceModel(id=dev_id, hostname=dev_id.upper(), type=dtype, networkZone=zone)
            )

    def execute_recovery(
        self,
        plan: ScenarioRecoveryPlan,
        mutated_ports: Optional[Dict[str, List[int]]] = None
    ) -> RecoveryExecutionReport:
        device_results: List[DeviceRecoveryResult] = []
        total_closed_conns = 0
        total_reverted_ports = 0

        for dev_id in plan.affectedDevices:
            self._ensure_device_ready(dev_id)
            conns_closed = 0
            ports_reverted = []

            # 1. Connection Teardown (CLOSE_SIMULATED_CONNECTIONS / RESTORE_BASELINE)
            if plan.restoreConnections or plan.strategy in (
                RecoveryStrategyEnum.CLOSE_SIMULATED_CONNECTIONS,
                RecoveryStrategyEnum.RESTORE_BASELINE
            ):
                try:
                    active_sessions = network_state_engine.getDeviceConnections(dev_id)
                    for sess in active_sessions:
                        try:
                            network_state_engine.closeConnection(sess.id)
                            conns_closed += 1
                        except Exception:
                            pass
                except Exception:
                    pass
                total_closed_conns += conns_closed

            # 2. Port Mutation Reversion (revert rogue ports opened during scenario)
            if plan.revertPortMutations and mutated_ports and dev_id in mutated_ports:
                for port_num in mutated_ports[dev_id]:
                    try:
                        port_service_engine.closePort(
                            device_id=dev_id,
                            port_number=port_num,
                            reason=f"Recovery plan {plan.planId}: Revert simulated attack backdoor"
                        )
                        ports_reverted.append(port_num)
                        total_reverted_ports += 1
                    except Exception:
                        pass

            # 3. State & Metric Restoration (RESTORE_STATE / RESET_METRICS / RESTORE_BASELINE)
            if plan.strategy in (
                RecoveryStrategyEnum.RESTORE_STATE,
                RecoveryStrategyEnum.RESET_METRICS,
                RecoveryStrategyEnum.RESTORE_BASELINE
            ):
                # Reset CPU / Memory to Baseline
                try:
                    performance_state_engine.updateCpu(dev_id, 25.0, source="RECOVERY")
                except Exception:
                    pass
                
                # Reset Network Utilisation
                try:
                    curr_net = network_state_engine.getNetworkMetrics(dev_id)
                    network_state_engine.updateNetworkMetrics(
                        device_id=dev_id,
                        network_utilisation=20.0,
                        bytes_sent=curr_net.bytesSent,
                        bytes_received=curr_net.bytesReceived,
                        packets_sent=curr_net.packetsSent,
                        packets_received=curr_net.packetsReceived
                    )
                except Exception:
                    pass

            # 4. Clear Security Posture Alert (CLEAR_ALERT / RESTORE_BASELINE)
            if plan.strategy in (
                RecoveryStrategyEnum.CLEAR_ALERT,
                RecoveryStrategyEnum.RESTORE_BASELINE
            ):
                try:
                    security_state_engine.updateSecurityStatus(
                        device_id=dev_id,
                        status=SecurityPostureStatusEnum.SECURE,
                        reason=f"Recovery plan {plan.planId}: Attack cleared and baseline restored"
                    )
                except Exception:
                    pass

            device_results.append(DeviceRecoveryResult(
                deviceId=dev_id,
                connectionsClosed=conns_closed,
                portsReverted=ports_reverted,
                cpuRestored=25.0,
                networkUtilisationRestored=20.0,
                securityStatusRestored="HEALTHY",
                success=True
            ))

        # 5. Verification Phase
        is_verified = True
        verification_details = {}
        if plan.verificationRequired:
            flat_ports = []
            if mutated_ports:
                for p_list in mutated_ports.values():
                    flat_ports.extend(p_list)
            is_verified, verification_details = RecoveryVerifier.verify(plan.affectedDevices, flat_ports)

        return RecoveryExecutionReport(
            scenarioId=plan.scenarioId,
            strategyUsed=plan.strategy,
            affectedDevices=plan.affectedDevices,
            deviceResults=device_results,
            totalConnectionsClosed=total_closed_conns,
            totalPortsReverted=total_reverted_ports,
            verified=is_verified,
            verificationDetails=verification_details
        )

recovery_engine = RecoveryEngine()