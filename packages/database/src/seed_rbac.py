import sys
import asyncio
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from packages.database.src.db_connection import db_manager
from packages.database.src.identity_repository import identity_repository

CANONICAL_PERMISSIONS = [
    ("VIEW_DASHBOARD", "Access to executive dashboard KPIs"),
    ("VIEW_TWIN", "Inspect 2D/3D Digital Twin graph topologies"),
    ("VIEW_ALERTS", "Access and search the security alerts hub"),
    ("CREATE_INCIDENT", "Escalate alerts into formal SOAR incident records"),
    ("INVESTIGATE_INCIDENT", "Participate in incident investigations"),
    ("RUN_SIMULATION", "Execute synthetic attack scenarios"),
    ("VIEW_RISK", "Inspect quantitative risk decomposition"),
    ("VIEW_ATTACK_PATH", "Analyze multi-hop attack vectors and blast radiuses"),
    ("VIEW_XAI", "Inspect TreeSHAP feature attributions"),
    ("VIEW_ML", "Review ML benchmark metrics and time-series early warnings"),
    ("VIEW_AUDIT", "Access forensic audit logs"),
    ("MANAGE_USERS", "Provision and manage operator credentials"),
    ("MANAGE_ROLES", "Configure role permissions and access policies"),
    ("MANAGE_SETTINGS", "Modify system engine parameters"),
    ("SIMULATE_RESPONSE", "Dispatch defensive response simulations")
]

CANONICAL_ROLES = {
    "ADMIN": {
        "description": "Full administrative control, settings management, and user provisioning.",
        "permissions": [p[0] for p in CANONICAL_PERMISSIONS]
    },
    "SECURITY_LEAD": {
        "description": "Incident closure authority, policy overrides, and risk model recalibration.",
        "permissions": [
            "VIEW_DASHBOARD", "VIEW_TWIN", "VIEW_ALERTS", "CREATE_INCIDENT",
            "INVESTIGATE_INCIDENT", "RUN_SIMULATION", "VIEW_RISK", "VIEW_ATTACK_PATH",
            "VIEW_XAI", "VIEW_ML", "VIEW_AUDIT", "SIMULATE_RESPONSE"
        ]
    },
    "SOC_ANALYST": {
        "description": "Daily operational alert triage, investigative queries, and simulated playbooks.",
        "permissions": [
            "VIEW_DASHBOARD", "VIEW_TWIN", "VIEW_ALERTS", "CREATE_INCIDENT",
            "INVESTIGATE_INCIDENT", "RUN_SIMULATION", "VIEW_RISK", "VIEW_ATTACK_PATH",
            "VIEW_XAI", "VIEW_ML", "SIMULATE_RESPONSE"
        ]
    },
    "AUDITOR": {
        "description": "Read-only access to tamper-evident forensic ledgers and compliance reports.",
        "permissions": [
            "VIEW_DASHBOARD", "VIEW_TWIN", "VIEW_ALERTS", "VIEW_RISK",
            "VIEW_ATTACK_PATH", "VIEW_AUDIT"
        ]
    },
    "VIEWER": {
        "description": "Restricted read-only visibility into executive KPIs and sanitized topology.",
        "permissions": ["VIEW_DASHBOARD", "VIEW_TWIN"]
    }
}

async def seed_rbac_data():
    """Seeds canonical roles, permissions, and initial admin operator into PostgreSQL."""
    await db_manager.connect()
    print("[*] Seeding Granular Security Permissions...")
    perm_map = {}
    for name, desc in CANONICAL_PERMISSIONS:
        p = await identity_repository.create_permission(name, desc)
        perm_map[name] = p.id

    print("[*] Seeding Canonical Enterprise Roles...")
    role_map = {}
    for role_name, config in CANONICAL_ROLES.items():
        r = await identity_repository.create_role(role_name, config["description"])
        role_map[role_name] = r.id

        # Bind role permissions
        for p_name in config["permissions"]:
            if p_name in perm_map:
                await identity_repository.assign_permission_to_role(r.id, perm_map[p_name])

    print("[*] Provisioning Default Security Admin Operator...")
    admin_role_id = role_map["ADMIN"]
    existing_admin = await identity_repository.get_user_by_username("sconnor")
    if not existing_admin:
        await identity_repository.create_user(
            username="sconnor",
            display_name="Sarah Connor",
            email="sconnor@cyberdefense.internal",
            password="SecureAdminPassword2026!",
            role_id=admin_role_id,
            status="ACTIVE"
        )
        print("    [+] Created default administrator 'sconnor'")
    else:
        print("    [*] Default administrator already exists.")

    await db_manager.disconnect()
    print("[+] RBAC Seeding Completed Successfully.")

if __name__ == "__main__":
    asyncio.run(seed_rbac_data())