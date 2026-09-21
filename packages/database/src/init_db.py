import sys
import asyncio
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.models import Base

async def provision_schema(drop_existing: bool = False):
    """Provision the declarative models into Neon Cloud PostgreSQL instance."""
    print("=" * 60)
    print("       NEON SCHEMA PROVISIONING PIPELINE")
    print("=" * 60 + "\n")

    await db_manager.connect()
    
    if db_manager._engine is None:
        raise RuntimeError("SQLAlchemy engine is not initialized. Check DATABASE_URL.")

    async with db_manager._engine.begin() as conn:
        if drop_existing:
            print("[WARN] Dropping existing schema tables...")
            await conn.run_sync(Base.metadata.drop_all)
        
        print("[INFO] Creating schema tables from models...")
        await conn.run_sync(Base.metadata.create_all)
    
    print("\n[PASS] Database schema provisioned cleanly via SQLAlchemy models.")
    await db_manager.disconnect()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CyberTwin Neon Schema Provisioning")
    parser.add_argument("--drop", action="store_true", help="Drop existing tables before creation")
    args = parser.parse_args()
    
    asyncio.run(provision_schema(drop_existing=args.drop))