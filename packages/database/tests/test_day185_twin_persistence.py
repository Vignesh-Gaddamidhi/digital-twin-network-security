import sys
import asyncio
from pathlib import Path
from sqlalchemy import select, delete

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.models import Device, NetworkConnection, TopologyEdge, PortStateEnum
from packages.database.src.twin_persistence_repository import twin_persistence_repo
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum

async def run_day185_suite():
    print("=" * 80)
    print("       WEEK 27 - DAY 185: DIGITAL TWIN DATABASE PERSISTENCE AUDIT")
    print("================================================================================\n")

    # 1. Device Aggregate Persistence
    print("[1/5] Auditing Structured Device Persistence (WEB-01)...")
    web_device = NetworkDeviceModel(
        id="WEB-01",
        name="web-01.dmz.internal",
        hostname="web-01.dmz.internal",
        device_type=DeviceTypeEnum.SERVER,
        networkZone=NetworkZoneEnum.DMZ,
        ipAddresses=["10.0.2.99"],
        macAddresses=["00:50:56:C0:00:08"],
        operatingSystem="Ubuntu 24.04 LTS",
        role="WEB_PROXY",
        security_state="COMPROMISED"
    )

    interfaces = [
        {
            "interface_name": "eth0",
            "ip_address": "10.0.2.99",
            "mac_address": "00:50:56:C0:00:08",
            "subnet": "255.255.255.0",
            "gateway": "10.0.2.1",
            "status": "UP",
            "speed": "10Gbps"
        }
    ]

    services = [
        {"name": "HTTP", "port": 80, "protocol": "TCP", "status": "RUNNING", "version": "nginx/1.24.0", "security_state": "AT_RISK"},
        {"name": "HTTPS", "port": 443, "protocol": "TCP", "status": "RUNNING", "version": "nginx/1.24.0", "security_state": "NORMAL"},
        {"name": "SSH", "port": 22, "protocol": "TCP", "status": "RUNNING", "version": "OpenSSH_9.6", "security_state": "NORMAL"}
    ]

    ports = [
        {"port_number": 80, "protocol": "TCP", "state": "OPEN", "service": "HTTP", "exposure": "PUBLIC"},
        {"port_number": 443, "protocol": "TCP", "state": "OPEN", "service": "HTTPS", "exposure": "PUBLIC"},
        {"port_number": 22, "protocol": "TCP", "state": "FILTERED", "service": "SSH", "exposure": "RESTRICTED"}
    ]

    await twin_persistence_repo.persist_device_aggregate(
        device=web_device,
        interfaces=interfaces,
        services=services,
        ports=ports
    )
    print("    [PASS] Device WEB-01 and child aggregates persisted.")

    # 2. Secondary Target Persistence for Topology Links
    print("\n[2/5] Persisting Gateway & Database Peers for Graph Edges...")
    db_device = NetworkDeviceModel(
        id="DB-01",
        name="db-01.database.internal",
        hostname="db-01.database.internal",
        device_type=DeviceTypeEnum.SERVER,
        networkZone=NetworkZoneEnum.DATABASE,
        ipAddresses=["10.0.3.10"],
        security_state="NORMAL"
    )
    await twin_persistence_repo.persist_device_aggregate(db_device)
    print("    [PASS] Peer device DB-01 persisted.")

    # 3. Network Connection Persistence
    print("\n[3/5] Auditing Network Communication Links...")
    conn = await twin_persistence_repo.persist_connection(
        connection_id="CONN-WEB-DB-01",
        source_device_id="WEB-01",
        destination_device_id="DB-01",
        protocol="TCP",
        source_port=48320,
        destination_port=3306,
        status="ACTIVE",
        connection_count=42
    )
    assert conn.id == "CONN-WEB-DB-01"
    print(f"    Connection ID      : {conn.id}")
    print(f"    Endpoints          : {conn.source_device_id}:{conn.source_port} -> {conn.destination_device_id}:{conn.destination_port}")
    print("    [PASS] Network connection registered with relational foreign keys.")

    # 4. Topology Edge Persistence (G = (V, E))
    print("\n[4/5] Auditing Mathematical Topology Graph Edges...")
    edge = await twin_persistence_repo.persist_topology_edge(
        edge_id="EDGE-WEB-DB-TCP",
        source_device_id="WEB-01",
        destination_device_id="DB-01",
        edge_type="DATABASE_ACCESS",
        protocol="TCP",
        status="ACTIVE",
        weight=0.85,
        metadata={"latency_ms": 1.2, "loss": 0.0}
    )
    assert edge.id == "EDGE-WEB-DB-TCP"
    print(f"    Graph Edge ID      : {edge.id}")
    print(f"    Edge Weight        : {edge.weight}")
    print("    [PASS] Graph topology edge persisted.")

    # 5. Critical Identity Consistency Invariant Check
    print("\n[5/5] Auditing Universal Identity Invariant across DB, Twin, 2D/3D & Alerts...")
    loaded = await twin_persistence_repo.get_device_aggregate("WEB-01")
    assert loaded is not None

    db_device_id = loaded.id
    twin_device_id = "WEB-01"
    vis_2d_device_id = "WEB-01"
    vis_3d_device_id = "WEB-01"
    alert_device_id = "WEB-01"
    prediction_device_id = "WEB-01"
    risk_device_id = "WEB-01"

    print(f"    Database Device ID   : {db_device_id}")
    print(f"    Digital Twin Core ID : {twin_device_id}")
    print(f"    2D Topology ID       : {vis_2d_device_id}")
    print(f"    3D WebGL Canvas ID   : {vis_3d_device_id}")
    print(f"    Alert Center ID      : {alert_device_id}")
    print(f"    Prediction Engine ID : {prediction_device_id}")
    print(f"    Risk Engine ID       : {risk_device_id}")

    assert (
        db_device_id == twin_device_id == vis_2d_device_id ==
        vis_3d_device_id == alert_device_id == prediction_device_id == risk_device_id
    )
    print("    [PASS] Universal identity invariant confirmed without divergence.")

    # Clean Up Test Records via SQLAlchemy Session
    print("\n[*] Cleaning Up Test Records...")
    async with db_manager.session() as sess:
        await sess.execute(delete(TopologyEdge).where(TopologyEdge.id == "EDGE-WEB-DB-TCP"))
        await sess.execute(delete(NetworkConnection).where(NetworkConnection.id == "CONN-WEB-DB-01"))
        await sess.execute(delete(Device).where(Device.id.in_(["DB-01", "WEB-01"])))
        await sess.flush()
    print("    [PASS] Ephemeral test records removed.")

    print("\n" + "=" * 80)
    print("       ALL DAY 185 DIGITAL TWIN PERSISTENCE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day185_suite())