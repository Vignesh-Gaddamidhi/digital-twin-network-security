import sys
import copy
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.core.twin_state import twin_engine, DeviceEntity, DeviceInterface, NetworkLinkEntity
from services.twin_engine.src.core.risk_engine import risk_engine
from services.twin_engine.src.api.main import bootstrap_security_grounding

class LivingDigitalTwinCore:
    """Demonstrates formal Digital Twin characteristics: synchronization, simulation, and lifecycle execution."""

    def __init__(self):
        bootstrap_security_grounding()
        self.lifecycle_stage = "INITIALIZE"
        self.simulated_branches: Dict[str, Any] = {}

    def get_canonical_state(self) -> Dict[str, Any]:
        return twin_engine.serialize_twin()

    def sync_telemetry_event(self, source_ip: str, dest_ip: str, dest_port: int, flags: str):
        """LIFECYCLE STAGE 4 & 6: Synchronize real-world telemetry into virtual graph state."""
        self.lifecycle_stage = "SYNC"
        target_device = next(
            (d for d in twin_engine.node_registry.values() if any(i.ip_address == dest_ip for i in d.interfaces)),
            None
        )
        if target_device:
            self.lifecycle_stage = "UPDATE"
            if flags == "S" and dest_port in (4444, 22):
                twin_engine.degrade_cia(target_device.id, "CONFIDENTIALITY", 0.35)
            return {
                "synchronized_node": target_device.id,
                "current_security_state": target_device.security_state,
                "cia": target_device.cia_score.model_dump()
            }
        return None

    def fork_simulation(self, branch_id: str) -> "LivingDigitalTwinCore":
        """LIFECYCLE STAGE 7: Creates an in-memory clone of the live twin for speculative What-If analysis."""
        cloned_twin = copy.deepcopy(self)
        cloned_twin.lifecycle_stage = "SIMULATE"
        self.simulated_branches[branch_id] = cloned_twin
        return cloned_twin

    def predict_next_attack_target(self, origin_node_id: str) -> Dict[str, Any]:
        """LIFECYCLE STAGE 8: Predicts adversary lateral trajectory based on topology edges and exposure."""
        origin_node = twin_engine.node_registry.get(origin_node_id)
        if not origin_node:
            return {"error": "Origin node not found"}

        # Traverse topology graph edges
        connected_candidates = []
        for target_id in twin_engine.topology.neighbors(origin_node_id):
            candidate = twin_engine.node_registry[target_id]
            if candidate.id == origin_node_id:
                continue

            # Calculate path transition probability based on criticality and CVSS flaws
            risk_profile = risk_engine.calculate_node_risk(candidate)
            score = (candidate.criticality * 0.4) + (risk_profile["composite_risk_score"] * 0.6)
            connected_candidates.append({
                "target_node_id": candidate.id,
                "hostname": candidate.hostname,
                "risk_score": risk_profile["composite_risk_score"],
                "lateral_pivot_probability": round(min(0.99, score / 100.0), 2)
            })

        # Also check nodes sharing the same subnet if traversing via Layer 2 switch
        if origin_node.type in ("SERVER", "WORKSTATION"):
            for candidate in twin_engine.node_registry.values():
                if candidate.id != origin_node_id and candidate.type in ("SERVER", "WORKSTATION"):
                    if not any(c["target_node_id"] == candidate.id for c in connected_candidates):
                        risk_profile = risk_engine.calculate_node_risk(candidate)
                        connected_candidates.append({
                            "target_node_id": candidate.id,
                            "hostname": candidate.hostname,
                            "risk_score": risk_profile["composite_risk_score"],
                            "lateral_pivot_probability": 0.75
                        })

        connected_candidates.sort(key=lambda x: x["lateral_pivot_probability"], reverse=True)
        top_target = connected_candidates[0] if connected_candidates else None

        return {
            "origin_compromised_node": origin_node_id,
            "lifecycle_stage": "PREDICT",
            "forecasted_next_target": top_target,
            "evaluated_paths": connected_candidates
        }

    def execute_containment_response(self, compromised_node_id: str) -> Dict[str, Any]:
        """LIFECYCLE STAGE 9: Simulates automated mitigation by isolating the node in the virtual topology."""
        node = twin_engine.node_registry.get(compromised_node_id)
        if not node:
            return {"error": "Node not found"}

        self.lifecycle_stage = "RESPOND"
        node.security_state = "ISOLATED"
        # Remove active links to isolate the compromised asset
        edges_to_remove = list(twin_engine.topology.edges(compromised_node_id))
        for u, v in edges_to_remove:
            twin_engine.topology.remove_edge(u, v)

        return {
            "action": "AUTOMATED_NODE_ISOLATION",
            "node_id": compromised_node_id,
            "security_state": node.security_state,
            "severed_links_count": len(edges_to_remove),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }