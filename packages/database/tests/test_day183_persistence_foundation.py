import sys
import asyncio
from pathlib import Path
from sqlalchemy import delete

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.models import Device
from packages.database.src.device_repository import device_repository
from packages.shared_types.src.network_device import NetworkDeviceModel, DeviceTypeEnum, NetworkZoneEnum

async def run_day183_suite():
    print("=" * 80)
    print("       WEEK 27 - DAY 183: POSTGRESQL ARCHITECTURE & PERSISTENCE AUDIT")
    print("================================================================================\n")

    # 1. Test Database Connectivity
    print("[1/4] Connecting to Neon Cloud PostgreSQL Instance...")
    await db_manager.connect()
    assert db_manager.is_connected is True
    print("    [PASS] Connected successfully via SSL.")

    # 2. Test Device Persistence (Upsert)
    print("\n[2/4] Testing Device Persistence via Repository Layer...")
    test_device = NetworkDeviceModel(
        id="SRV-NEON-01",
        name="srv-neon-db-test",
        hostname="srv-neon-db-test",
        device_type=DeviceTypeEnum.SERVER,
        networkZone=NetworkZoneEnum.DATABASE,
        ipAddresses=["10.0.3.50"],
        security_state="NORMAL"
    )
    saved = await device_repository.upsert_device(test_device)
    assert saved.id == "SRV-NEON-01"
    print(f"    Saved Device ID    : {saved.id}")
    print(f"    Saved Hostname     : {saved.hostname}")
    print(f"    Saved Network Zone : {saved.network_zone}")
    print("    [PASS] Device entity upserted to PostgreSQL.")

    # 3. Test Query Retrieval
    print("\n[3/4] Testing Relational Query Retrieval...")
    queried = await device_repository.get_device_by_id("SRV-NEON-01")
    assert queried is not None
    assert queried.id == "SRV-NEON-01"
    print(f"    Retrieved ID       : {queried.id}")
    print(f"    Security State     : {queried.security_state}")
    print("    [PASS] Relational query retrieval verified.")

    # 4. Clean Up Test Record & Disconnect
    print("\n[4/4] Cleaning Up Test Artifacts & Closing Connection...")
    async with db_manager.session() as sess:
        await sess.execute(delete(Device).where(Device.id == "SRV-NEON-01"))
        await sess.flush()
    await db_manager.disconnect()
    assert db_manager.is_connected is False
    print("    [PASS] Test artifact cleaned and session disconnected.")

    print("\n" + "=" * 80)
    print("       ALL DAY 183 POSTGRESQL PERSISTENCE FOUNDATION TESTS PASSED")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day183_suite())