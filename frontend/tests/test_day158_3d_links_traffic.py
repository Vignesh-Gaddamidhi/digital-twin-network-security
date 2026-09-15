import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.digital_twin.attack_path.graph.twin_graph_synchronizer import twin_graph_synchronizer
from services.digital_twin.attack_path.graph.attack_path_graph import attack_path_graph
from frontend.topology.link_3d_models import (
    LinkStateEnum, TrafficFlowDirectionEnum, TrafficProtocolType
)
from frontend.topology.device_3d_renderer_engine import device_3d_renderer_engine
from frontend.topology.link_3d_renderer_engine import link_3d_renderer_engine

def run_day158_suite():
    print("=" * 80)
    print("       WEEK 23 - DAY 158: 3D LINKS, TOPOLOGY & TRAFFIC PARTICLES AUDIT")
    print("=" * 80 + "\n")

    twin_graph_synchronizer._seed_default_twin_state()
    twin_graph_synchronizer.full_synchronization()
    device_3d_renderer_engine.sync_devices_from_twin()
    link_3d_renderer_engine.sync_links_from_twin()

    # 1. Topology Matching & Link Integrity
    print("[1/8] Auditing 3D Topology Link Extraction from Twin Graph...")
    snap = link_3d_renderer_engine.get_snapshot()
    print(f"    Total Links Extracted : {snap.totalLinks}")
    print(f"    Active Links Count    : {snap.activeLinksCount}")

    assert snap.totalLinks == len(attack_path_graph.edges)
    assert snap.totalLinks >= 4
    print("    [PASS] 3D links match backend graph edges without duplicate entries.")

    # 2. Source/Destination Coordinates & Arc Elevation
    print("\n[2/8] Auditing Link Endpoint Vectors & Parabolic Arc Lift...")
    link_web_db = next(l for l in snap.links.values() if l.sourceDeviceId == "WEB-01" and l.destinationDeviceId == "DB-01")
    print(f"    WEB-01 -> DB-01 Arc:")
    print(f"      Source Pos  : ({link_web_db.sourcePos.x}, {link_web_db.sourcePos.y}, {link_web_db.sourcePos.z})")
    print(f"      Mid-Arc Pos : ({link_web_db.midArcPos.x}, {link_web_db.midArcPos.y}, {link_web_db.midArcPos.z})")
    print(f"      Dest Pos    : ({link_web_db.destinationPos.x}, {link_web_db.destinationPos.y}, {link_web_db.destinationPos.z})")

    assert link_web_db.midArcPos.y > link_web_db.sourcePos.y  # Arc lift verified
    assert link_web_db.destinationPort == 3306
    print("    [PASS] Endpoints and arc geometry correctly span 3D world coordinates.")

    # 3. Protocol Visualization (TCP, UDP, ICMP, HTTP, HTTPS, DNS, SSH)
    print("\n[3/8] Auditing Multi-Protocol Color Coding & Velocity Parameters...")
    protocols = [
        TrafficProtocolType.TCP, TrafficProtocolType.UDP, TrafficProtocolType.ICMP,
        TrafficProtocolType.HTTP, TrafficProtocolType.HTTPS, TrafficProtocolType.DNS,
        TrafficProtocolType.SSH
    ]
    target_lid = list(snap.links.keys())[0]
    for proto in protocols:
        p = link_3d_renderer_engine.inject_traffic_flow(target_lid, protocol=proto)
        assert p is not None
        expected_color = link_3d_renderer_engine.PROTOCOL_COLORS[proto]
        expected_speed = link_3d_renderer_engine.PROTOCOL_SPEEDS[proto]
        print(f"    Protocol: {proto.value:<6} -> Color: {p.colorHex:<8} | Speed: {p.speed:.3f}")
        assert p.colorHex == expected_color
        assert p.speed == expected_speed
    print("    [PASS] All 7 protocols visual properties verified.")

    # 4. Traffic Flow Direction (FORWARD vs REVERSE)
    print("\n[4/8] Auditing Bidirectional Traffic Flow (FORWARD vs REVERSE)...")
    link_3d_renderer_engine.clear_all_traffic()

    p_fwd = link_3d_renderer_engine.inject_traffic_flow(target_lid, direction=TrafficFlowDirectionEnum.FORWARD)
    p_rev = link_3d_renderer_engine.inject_traffic_flow(target_lid, direction=TrafficFlowDirectionEnum.REVERSE)

    print(f"    FORWARD Flow Initial Progress : T={p_fwd.progressT}")
    print(f"    REVERSE Flow Initial Progress : T={p_rev.progressT}")
    assert p_fwd.progressT == 0.0
    assert p_rev.progressT == 1.0

    # Step simulation
    link_3d_renderer_engine.step_particle_simulation()
    print(f"    FORWARD Flow After Step       : T={p_fwd.progressT:.3f} (> 0.0)")
    print(f"    REVERSE Flow After Step       : T={p_rev.progressT:.3f} (< 1.0)")
    assert p_fwd.progressT > 0.0
    assert p_rev.progressT < 1.0
    print("    [PASS] Forward and Reverse flows traverse in opposite directions.")

    # 5. Link Status Updates (ACTIVE -> BLOCKED)
    print("\n[5/8] Auditing Link Status Updates & Blocked Enforcement...")
    link_3d_renderer_engine.update_link_status(target_lid, LinkStateEnum.BLOCKED)
    assert snap.links[target_lid].status == LinkStateEnum.BLOCKED
    assert snap.links[target_lid].isReachable is False

    # Injected packet on blocked link should be dropped
    p_blocked = link_3d_renderer_engine.inject_traffic_flow(target_lid)
    assert p_blocked is None
    print("    Packet dropped on BLOCKED link verified.")

    # Restore link
    link_3d_renderer_engine.update_link_status(target_lid, LinkStateEnum.ACTIVE)
    assert snap.links[target_lid].status == LinkStateEnum.ACTIVE
    print("    [PASS] Link status state machine enforces flow blocking.")

    # 6. Particle Lifecycle Completion & Recycling
    print("\n[6/8] Auditing Particle Progression & Natural Termination...")
    link_3d_renderer_engine.clear_all_traffic()
    _ = link_3d_renderer_engine.inject_traffic_flow(target_lid, protocol=TrafficProtocolType.DNS)

    initial_active = link_3d_renderer_engine.get_snapshot().totalActiveParticles
    assert initial_active == 1

    # Step repeatedly until particle reaches progressT >= 1.0
    recycled_total = 0
    for _ in range(40):
        recycled_total += link_3d_renderer_engine.step_particle_simulation()

    final_active = link_3d_renderer_engine.get_snapshot().totalActiveParticles
    print(f"    Particles Recycled: {recycled_total} | Active Remaining: {final_active}")
    assert recycled_total == 1
    assert final_active == 0
    print("    [PASS] Particles complete travel and dereference cleanly.")

    # 7. Traffic Clear Action
    print("\n[7/8] Auditing Emergency Traffic Clear Action...")
    for _ in range(10):
        link_3d_renderer_engine.inject_traffic_flow(target_lid)
    assert link_3d_renderer_engine.get_snapshot().totalActiveParticles == 10

    link_3d_renderer_engine.clear_all_traffic()
    assert link_3d_renderer_engine.get_snapshot().totalActiveParticles == 0
    print("    [PASS] All active particle allocations flushed cleanly.")

    # 8. High Event Volume Bounded Capacity
    print("\n[8/8] Auditing Hard Buffer Limit Clamping (Under Volumetric Flooding)...")
    link_3d_renderer_engine.clear_all_traffic()
    dropped_count = 0
    for _ in range(700):  # Exceeds max_particle_capacity of 500
        res = link_3d_renderer_engine.inject_traffic_flow(target_lid)
        if res is None:
            dropped_count += 1

    total_clamped = link_3d_renderer_engine.get_snapshot().totalActiveParticles
    print(f"    Injected Floods : 700")
    print(f"    Active Clamped  : {total_clamped} (Limit: {link_3d_renderer_engine.max_particle_capacity})")
    print(f"    Dropped Floods  : {dropped_count}")

    assert total_clamped == link_3d_renderer_engine.max_particle_capacity
    assert dropped_count == 200
    print("    [PASS] Particle buffer enforces limit to preserve WebGL framerate.")

    print("\n" + "=" * 80)
    print("       ALL DAY 158 3D LINKS & TRAFFIC TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    run_day158_suite()