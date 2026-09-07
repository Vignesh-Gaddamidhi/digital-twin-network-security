import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.twin_engine.src.api.main import bootstrap_security_grounding
from services.twin_engine.src.core.twin_state import twin_engine

def run_device_model_test():
    print("================================================================================")
    print("       WEEK 4 - DAY 23: DEVICE DIGITAL TWIN SCHEMA & ENTITY AUDIT               ")
    print("================================================================================\n")

    # Bootstrap enriched topology
    bootstrap_security_grounding()

    print("[1/3] Auditing Device Canonical Identifiers & Operating Systems...")
    for dev_id, dev in twin_engine.node_registry.items():
        print(f"  - Device [{dev.id}] | Hostname: {dev.hostname:14s} | Type: {dev.type:12s} | OS: {dev.os.name} ({dev.os.version})")
        assert dev.id is not None
        assert dev.os.architecture in ("x86_64", "x64", "arm64")

    print("\n[2/3] Auditing Structured Port Registry & Service Daemons on D002 (Web Server)...")
    srv = twin_engine.node_registry["D002"]
    print(f"  Device: {srv.hostname} (Criticality: {srv.criticality})")
    print(f"  Operating System: {srv.os.name} {srv.os.version} (Kernel: {srv.os.kernel_release})")
    
    # Check Ports
    print("\n  Open Port Registry:")
    for p in srv.detailed_ports:
        print(f"    Port {p.port_number:5d}/{p.protocol:3s} | State: {p.state:8s} | Service: {p.bound_service:10s} | Exposed: {p.is_exposed}")
    assert len(srv.detailed_ports) == 3
    assert any(p.port_number == 80 and p.is_exposed for p in srv.detailed_ports)

    # Check Services
    print("\n  Running Application Services:")
    for s in srv.detailed_services:
        print(f"    Service: {s.name:15s} | Ver: {s.version:10s} | Status: {s.status:8s} | Associated CVEs: {s.associated_cves}")
    assert any(s.name == "nginx" and s.status == "RUNNING" for s in srv.detailed_services)
    assert any(s.name == "openssh" and "CVE-2023-38408" in s.associated_cves for s in srv.detailed_services)

    print("\n[3/3] Auditing Multi-Homed Gateway Router (D004)...")
    rtr = twin_engine.node_registry["D004"]
    print(f"  Device: {rtr.hostname} | Interfaces Count: {len(rtr.interfaces)}")
    for iface in rtr.interfaces:
        print(f"    Interface: {iface.interface_id:6s} | IP: {iface.ip_address:15s} | MAC: {iface.mac_address} | Subnet: {iface.subnet}")
    assert len(rtr.interfaces) == 2, "Router must have exactly 2 interfaces (LAN + WAN)"

    print("\n================================================================================")
    print("           DEVICE DIGITAL TWIN SCHEMA VERIFIED SUCCESSFULLY                     ")
    print("================================================================================")

if __name__ == "__main__":
    run_device_model_test()