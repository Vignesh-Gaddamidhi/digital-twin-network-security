import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[4]
ENTRY_ARTIFACTS_DIR = ROOT_DIR / "services" / "digital_twin" / "ml" / "artifacts" / "attack_path"
ENTRY_POINTS_FILE = ENTRY_ARTIFACTS_DIR / "entry_points.json"

from services.digital_twin.attack_path.graph.graph_models import (
    NodeTypeEnum, AttackPathNode, AttackPathEdge
)
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from services.digital_twin.attack_path.graph.security_zone_models import NetworkZoneEnum
from services.digital_twin.attack_path.nodes.entry_point_models import (
    StateSourceEnum, TargetTypeEnum, EntryPointScore, AttackTargetDefinition, DeviceCompromiseState
)

class EntryPointEngine:
    """Manages attacker representation, entry-point evaluation, compromise state, and target definition."""

    def __init__(self, artifacts_dir: Path = ENTRY_ARTIFACTS_DIR):
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.compromise_states: Dict[str, DeviceCompromiseState] = {}
        self.registered_targets: Dict[str, AttackTargetDefinition] = {}

    def create_attacker_node(
        self,
        node_id: str = "ATTACKER-01",
        hostname: str = "adversary.external.net",
        ip: str = "198.51.100.24"
    ) -> AttackPathNode:
        node = AttackPathNode(
            nodeId=node_id,
            deviceId=node_id,
            nodeType=NodeTypeEnum.ATTACKER,
            hostname=hostname,
            ipAddresses=[ip],
            deviceType="External Threat Actor",
            zone=NetworkZoneEnum.INTERNET.value,
            assetCriticality="VERY_LOW",
            reachable=True
        )
        if node_id not in attack_path_graph.nodes:
            attack_path_graph.add_node(node)
        return node

    def set_simulation_compromise(
        self,
        device_id: str,
        state: str = "COMPROMISED",
        scenario_id: Optional[str] = None
    ) -> DeviceCompromiseState:
        node = attack_path_graph.get_node(device_id)
        comp = DeviceCompromiseState(
            deviceId=device_id,
            confirmedState=state,
            predictedState=node.securityState,
            stateSource=StateSourceEnum.CONFIRMED_SIMULATION_STATE,
            compromiseTimestamp="2026-09-14T12:00:00Z",
            scenarioId=scenario_id,
            isolationActive=(state == "ISOLATED")
        )
        self.compromise_states[device_id] = comp
        node.securityState = state
        return comp

    def set_predicted_compromise(
        self,
        device_id: str,
        predicted_state: str = "AT_RISK"
    ) -> DeviceCompromiseState:
        node = attack_path_graph.get_node(device_id)
        current_confirmed = self.compromise_states.get(device_id)
        confirmed_val = current_confirmed.confirmedState if current_confirmed else "NORMAL"

        comp = DeviceCompromiseState(
            deviceId=device_id,
            confirmedState=confirmed_val,
            predictedState=predicted_state,
            stateSource=StateSourceEnum.ML_PREDICTED_STATE,
            isolationActive=(confirmed_val == "ISOLATED")
        )
        self.compromise_states[device_id] = comp
        return comp

    def evaluate_entry_point(
        self,
        device_id: str,
        threat_probability: float = 0.0
    ) -> EntryPointScore:
        node = attack_path_graph.get_node(device_id)

        # 1. External Exposure
        if node.zone in (NetworkZoneEnum.INTERNET.value, NetworkZoneEnum.DMZ.value):
            exposure = 1.0
        elif node.zone == NetworkZoneEnum.INTERNAL.value:
            exposure = 0.5
        else:
            exposure = 0.2

        # 2. Reachability from untrusted edges
        incoming = [e for e in attack_path_graph.edges.values() if e.destinationNode == device_id and e.reachable]
        reachability = 1.0 if len(incoming) > 0 else 0.0

        # Check for isolated/quarantined devices
        comp = self.compromise_states.get(device_id)
        if comp and comp.isolationActive:
            reachability = 0.0

        # 3. Vulnerability status
        has_unpatched = len(node.vulnerabilities) > 0
        vuln_score = 1.0 if has_unpatched else 0.2

        # 4. Asset Risk (Normalized)
        asset_risk = min(1.0, max(0.0, node.riskScore / 100.0))

        # 5. Composite Score Calculation
        composite = round(
            (0.25 * exposure) +
            (0.20 * reachability) +
            (0.25 * vuln_score) +
            (0.15 * asset_risk) +
            (0.15 * threat_probability),
            4
        )

        rationale = (
            f"Node {device_id} scored {composite:.2f} as candidate entry point "
            f"(Exposure: {exposure:.2f}, Reachable: {reachability:.2f}, Vuln: {vuln_score:.2f})."
        )

        return EntryPointScore(
            deviceId=device_id,
            exposure=exposure,
            reachability=reachability,
            vulnerability=vuln_score,
            assetRisk=asset_risk,
            threatProbability=threat_probability,
            compositeScore=composite,
            rationale=rationale
        )

    def register_target(
        self,
        device_id: str,
        target_type: TargetTypeEnum = TargetTypeEnum.DATABASE,
        service_name: Optional[str] = None,
        port: Optional[int] = None,
        description: str = ""
    ) -> AttackTargetDefinition:
        node = attack_path_graph.get_node(device_id)
        target = AttackTargetDefinition(
            deviceId=device_id,
            targetType=target_type,
            assetCriticality=node.assetCriticality,
            serviceName=service_name,
            port=port,
            targetZone=node.zone,
            description=description or f"Designated crown jewel target {device_id}"
        )
        self.registered_targets[device_id] = target
        return target

    def clear(self):
        self.compromise_states.clear()
        self.registered_targets.clear()

entry_point_engine = EntryPointEngine()