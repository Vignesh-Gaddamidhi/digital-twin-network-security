import sys
import asyncio
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.models import Device
from sqlalchemy import select

async def seed_canonical_devices():
    await db_manager.connect()
    canonical = [
        {"id": "WEB-01", "hostname": "web-01.internal", "device_type": "SERVER", "network_zone": "DMZ", "primary_ip": "192.168.10.10"},
        {"id": "DB-01", "hostname": "db-01.internal", "device_type": "DATABASE", "network_zone": "INTERNAL", "primary_ip": "192.168.20.10"},
        {"id": "CLIENT-01", "hostname": "client-01.internal", "device_type": "WORKSTATION", "network_zone": "USER", "primary_ip": "192.168.30.15"},
        {"id": "ROUTER-01", "hostname": "router-01.internal", "device_type": "ROUTER", "network_zone": "GATEWAY", "primary_ip": "192.168.1.1"}
    ]
    async with db_manager.session() as sess:
        for d in canonical:
            res = await sess.execute(select(Device).where(Device.id == d["id"]))
            if not res.scalar_one_or_none():
                dev = Device(
                    id=d["id"],
                    hostname=d["hostname"],
                    device_type=d["device_type"],
                    network_zone=d["network_zone"],
                    primary_ip=d["primary_ip"],
                    security_state="NORMAL",
                    operational_state="UP",
                    risk_score=0.0,
                    is_compromised=False
                )
                sess.add(dev)
        await sess.commit()
    print("[PASS] Canonical network devices seeded into PostgreSQL.")
    await db_manager.disconnect()

if __name__ == "__main__":
    asyncio.run(seed_canonical_devices())