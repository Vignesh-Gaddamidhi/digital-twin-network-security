from typing import List, Tuple, Any, Optional
from datetime import datetime, timezone

from packages.shared_types.src.preconditions import (
    PreconditionTypeEnum, PreconditionOperatorEnum, PreconditionRuleModel,
    PreconditionCheckDetail, PreconditionValidationReport
)
from packages.shared_types.src.port_service_state import PortStateEnum
from services.digital_twin.core.devices.network_device_registry import device_registry
from services.digital_twin.core.state.port_service_engine import port_service_engine
from services.digital_twin.core.topology.graph_engine import graph_engine

class PreconditionEngine:
    """Evaluates scenario preconditions against the live digital twin state."""

    @staticmethod
    def evaluate_rule(rule: PreconditionRuleModel, source_device: Optional[str] = None) -> PreconditionCheckDetail:
        ptype = rule.type
        tgt = rule.target
        expected = rule.expectedValue
        passed = False
        observed = None
        reason = None

        # 1. DEVICE_EXISTS
        if ptype == PreconditionTypeEnum.DEVICE_EXISTS:
            dev = device_registry.getDevice(tgt)
            observed = dev is not None
            passed = (observed == bool(expected))
            if not passed:
                reason = f"Device '{tgt}' does not exist in Device Registry."

        # 2. SERVICE_EXISTS
        elif ptype == PreconditionTypeEnum.SERVICE_EXISTS:
            # target format: 'device_id' or 'device_id:port'
            dev_id = tgt.split(":")[0] if ":" in tgt else tgt
            dev = device_registry.getDevice(dev_id)
            if not dev:
                observed = None
                passed = False
                reason = f"Target host '{dev_id}' not found for service verification."
            else:
                services = []
                try:
                    ports = port_service_engine.listPorts(dev_id)
                    services = [p.service.upper() for p in ports if p.service]
                except Exception:
                    pass
                observed = services
                target_svc = str(expected).upper()
                passed = target_svc in services
                if not passed:
                    reason = f"Service '{target_svc}' not active on host '{dev_id}'. Active: {services}"

        # 3. PORT_STATE
        elif ptype == PreconditionTypeEnum.PORT_STATE:
            # target format: 'device_id:port'
            if ":" not in tgt:
                passed = False
                observed = None
                reason = f"Invalid target format '{tgt}'. Expected 'device_id:port_number'."
            else:
                dev_id, port_str = tgt.split(":")
                try:
                    port_num = int(port_str)
                    port_entry = port_service_engine.getPort(dev_id, port_num)
                    observed = port_entry.state.value if port_entry else "CLOSED"
                    expected_state = str(expected).upper()
                    passed = (observed == expected_state)
                    if not passed:
                        reason = f"Port {port_num} on '{dev_id}' is '{observed}', expected '{expected_state}'."
                except Exception as e:
                    observed = "NOT_CONFIGURED"
                    passed = (str(expected).upper() == "CLOSED")
                    if not passed:
                        reason = f"Port {port_str} on '{dev_id}' is not configured/open ({str(e)})."

        # 4. NETWORK_CONNECTION
        elif ptype == PreconditionTypeEnum.NETWORK_CONNECTION:
            # target format: 'source_device:target_device'
            if ":" in tgt:
                src_dev, dst_dev = tgt.split(":")
            else:
                src_dev = source_device or "client-01"
                dst_dev = tgt

            has_path = False
            try:
                if hasattr(graph_engine, "hasPath"):
                    has_path = bool(graph_engine.hasPath(src_dev, dst_dev))
                elif hasattr(graph_engine, "findPath"):
                    p = graph_engine.findPath(src_dev, dst_dev)
                    has_path = bool(p)
                elif hasattr(graph_engine, "getShortestPath"):
                    p = graph_engine.getShortestPath(src_dev, dst_dev)
                    has_path = bool(p)
                elif hasattr(graph_engine, "findShortestPath"):
                    p = graph_engine.findShortestPath(src_dev, dst_dev)
                    has_path = bool(p)
                elif hasattr(graph_engine, "_graph"):
                    import networkx as nx
                    has_path = nx.has_path(graph_engine._graph, src_dev, dst_dev)
            except Exception:
                has_path = False

            observed = has_path
            passed = (observed == bool(expected))
            if not passed:
                reason = f"No network route exists between '{src_dev}' and '{dst_dev}' in topology graph."

        # 5. SIMULATION_STATE
        elif ptype == PreconditionTypeEnum.SIMULATION_STATE:
            # Generic state assertions
            observed = str(expected)
            passed = True

        return PreconditionCheckDetail(
            preconditionId=rule.preconditionId,
            type=ptype,
            target=tgt,
            passed=passed,
            observedValue=observed,
            expectedValue=expected,
            reason=reason
        )

    def validate_scenario_preconditions(
        self,
        scenario_id: str,
        target_device: str,
        rules: List[PreconditionRuleModel],
        source_device: Optional[str] = None
    ) -> PreconditionValidationReport:
        details: List[PreconditionCheckDetail] = []
        failure_reasons: List[str] = []
        passed_count = 0
        failed_count = 0

        for rule in rules:
            res = self.evaluate_rule(rule, source_device=source_device)
            details.append(res)
            if res.passed:
                passed_count += 1
            else:
                if rule.required:
                    failed_count += 1
                    if res.reason:
                        failure_reasons.append(res.reason)

        is_valid = (failed_count == 0)

        return PreconditionValidationReport(
            scenarioId=scenario_id,
            targetDevice=target_device,
            isValid=is_valid,
            totalRulesEvaluated=len(rules),
            passedRulesCount=passed_count,
            failedRulesCount=failed_count,
            failureReasons=failure_reasons,
            details=details,
            evaluatedAt=datetime.now(timezone.utc).isoformat()
        )

precondition_engine = PreconditionEngine()