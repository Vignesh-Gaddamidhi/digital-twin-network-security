import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine
from packages.shared_types.src.topology import ConnectionEntity

def run_topology_validation_suite():
    print("================================================================================")
    print("      WEEK 4 - DAY 24: NETWORK TOPOLOGY DIGITAL TWIN GRAPH AUDIT                ")
    print("================================================================================\n")

    # 1. Bootstrap topology
    bootstrap_security_grounding()
    topo = twin_engine.serialize_twin()
    print(f"[*] Serialized Topology Graph: {len(topo['devices'])} devices, {len(topo['connections'])} connection records.")

    # Query 1: Is PC1 connected to the network?
    print("\n[Query 1] Is D001 (ws-pc-01) connected to the network?")
    d001_peers = twin_engine.get_reachable_devices("D001")
    is_d001_connected = len(d001_peers) > 0
    print(f"    Answer: {'YES' if is_d001_connected else 'NO'} (Can reach {len(d001_peers)} peer devices)")
    assert is_d001_connected, "D001 should have active network connectivity"

    # Query 2: What devices can PC1 reach?
    print("\n[Query 2] What devices can D001 reach?")
    for peer in d001_peers:
        print(f"    - [{peer['id']}] {peer['hostname']:14s} | Role: {peer['role']:18s} | State: {peer['security_state']}")
    assert len(d001_peers) == 4, "D001 should be able to reach all 4 peers via D005 switch"

    # Query 3: What is PC1's path to the Server (D002)?
    print("\n[Query 3] What is D001's transit path to D002 (Web Server)?")
    path_res = twin_engine.find_path("D001", "D002")
    print(f"    Connected: {path_res.is_connected}")
    print(f"    Hops     : {' -> '.join(path_res.traversed_devices)} ({path_res.hop_count} hops)")
    print(f"    Latency  : {path_res.total_latency_ms} ms")
    assert path_res.is_connected
    assert path_res.path_hops == ["D001", "D005", "D002"]
    assert path_res.hop_count == 2

    # Query 4: Which device is connected to the Router (D004)?
    print("\n[Query 4] Which device is directly connected to D004 (rtr-gw-01)?")
    rtr_neighbors = list(twin_engine.topology.to_undirected().neighbors("D004"))
    rtr_neighbor_names = [twin_engine.node_registry[n].hostname for n in rtr_neighbors]
    print(f"    Direct Neighbor: {', '.join(rtr_neighbor_names)} ({rtr_neighbors})")
    assert "D005" in rtr_neighbors, "D004 must be connected to Core Switch D005"

    # Query 5: Which devices depend on the Switch (D005)?
    print("\n[Query 5] Which devices depend on D005 (Core Switch)?")
    critical_bridges = twin_engine.find_critical_bridges()
    print(f"    Network Articulation Points: {critical_bridges}")
    assert "D005" in critical_bridges, "D005 must be identified as the single point of failure (articulation point)"
    print(f"    Impact Analysis: Failure or isolation of D005 severs {len(twin_engine.node_registry) - 1} endpoints.")

    # Bonus: Dynamic Service Connection Test
    print("\n[Bonus] Registering dynamic Layer 4 TCP session (D001:54321 -> D002:443)...")
    service_session = ConnectionEntity(
        source_device="D001",
        destination_device="D002",
        connection_type="SERVICE_SESSION",
        protocol="TCP",
        source_port=54321,
        destination_port=443,
        status="ACTIVE"
    )
    twin_engine.add_connection(service_session)
    updated_topo = twin_engine.serialize_twin()
    print(f"    Active Connections Now Tracked: {len(updated_topo['connections'])}")
    assert len(updated_topo['connections']) == 5, "Expected 5 connection objects after session registration"

    print("\n================================================================================")
    print("      NETWORK TOPOLOGY DIGITAL TWIN GRAPH AUDIT COMPLETED SUCCESSFULLY          ")
    print("================================================================================")

if __name__ == "__main__":
    run_topology_validation_suite()