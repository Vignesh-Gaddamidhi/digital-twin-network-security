import sys
import asyncio
from pathlib import Path
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.identity_repository import identity_repository

async def run_day184_suite():
    print("=" * 80)
    print("       WEEK 27 - DAY 184: IDENTITY & RBAC DATABASE PERSISTENCE AUDIT")
    print("================================================================================\n")

    await db_manager.connect()

    # 1. Bcrypt Password Hashing & Verification
    print("[1/5] Auditing Password Security & Bcrypt Hashing...")
    raw_pass = "SuperSecretSOC2026!"
    hashed = identity_repository.hash_password(raw_pass)
    assert hashed != raw_pass
    assert identity_repository.verify_password(raw_pass, hashed) is True
    assert identity_repository.verify_password("WrongPassword!", hashed) is False
    print("    [PASS] Passwords securely hashed with valid verification.")

    # 2. Role & Granular Permission Linkage
    print("\n[2/5] Auditing Role & Permission Join Mapping (Role: SOC_ANALYST)...")
    analyst_role = await identity_repository.get_role_by_name("SOC_ANALYST")
    assert analyst_role is not None
    perms = [rp.permission.name for rp in analyst_role.rolePermissions]
    print(f"    Role Name          : {analyst_role.name}")
    print(f"    Permissions Count  : {len(perms)}")
    print(f"    Sample Permissions : {', '.join(perms[:4])}")
    assert "VIEW_ALERTS" in perms
    assert "INVESTIGATE_INCIDENT" in perms
    assert "MANAGE_USERS" not in perms
    print("    [PASS] Granular RBAC join resolution confirmed.")

    # 3. User Creation with Role Binding
    print("\n[3/5] Auditing User Account Creation & Role Association...")
    test_user = await identity_repository.create_user(
        username="mwright_test",
        display_name="Marcus Wright",
        email="mwright_test@cyberdefense.internal",
        password="MarcusPassword2026!",
        role_id=analyst_role.id,
        status="ACTIVE"
    )
    assert test_user.id is not None
    assert test_user.username == "mwright_test"
    assert test_user.role.name == "SOC_ANALYST"
    print(f"    Created User ID   : {test_user.id}")
    print(f"    Assigned Role     : {test_user.role.name}")
    print(f"    Account Status    : {test_user.status}")
    print("    [PASS] User record persisted with foreign-key role integrity.")

    # 4. User Modification & Status Lifecycle Transition
    print("\n[4/5] Auditing Account Update & Status Mutation...")
    updated_user = await identity_repository.update_user(
        user_id=test_user.id,
        display_name="Marcus Wright (Lead)",
        status="LOCKED",
        last_activity=datetime.now(timezone.utc)
    )
    assert updated_user.displayName == "Marcus Wright (Lead)"
    assert updated_user.status == "LOCKED"
    assert updated_user.lastActivity is not None
    print(f"    Updated Display   : {updated_user.displayName}")
    print(f"    Updated Status    : {updated_user.status}")
    print("    [PASS] User state mutation and last_activity tracking verified.")

    # 5. Cleanup Test Artifacts
    print("\n[5/5] Cleaning Up Ephemeral Test Records...")
    prisma = db_manager.client
    await prisma.user.delete(where={"id": test_user.id})
    deleted_check = await identity_repository.get_user(test_user.id)
    assert deleted_check is None
    print("    [PASS] Test user successfully deleted.")

    await db_manager.disconnect()
    print("\n" + "=" * 80)
    print("       ALL DAY 184 IDENTITY & RBAC PERSISTENCE TESTS PASSED CLEANLY")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(run_day184_suite())