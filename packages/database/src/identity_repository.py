from typing import List, Optional, Dict, Any
import bcrypt
from datetime import datetime, timezone
from packages.database.src.db_connection import db_manager

class IdentityRepository:
    """Data Access Layer for Users, Roles, Permissions, and RBAC mapping."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Securely hashes plaintext password with a bcrypt salt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verifies plaintext against a stored bcrypt hash."""
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

    # ==================== PERMISSIONS ====================

    @staticmethod
    async def create_permission(name: str, description: Optional[str] = None) -> Any:
        prisma = db_manager.client
        return await prisma.permission.upsert(
            where={"name": name},
            data={
                "create": {"name": name, "description": description},
                "update": {"description": description}
            }
        )

    @staticmethod
    async def list_permissions() -> List[Any]:
        prisma = db_manager.client
        return await prisma.permission.find_many(order={"name": "asc"})

    # ==================== ROLES ====================

    @staticmethod
    async def create_role(name: str, description: Optional[str] = None) -> Any:
        prisma = db_manager.client
        return await prisma.role.upsert(
            where={"name": name},
            data={
                "create": {"name": name, "description": description},
                "update": {"description": description}
            }
        )

    @staticmethod
    async def get_role(role_id: str) -> Optional[Any]:
        prisma = db_manager.client
        return await prisma.role.find_unique(
            where={"id": role_id},
            include={"rolePermissions": {"include": {"permission": True}}}
        )

    @staticmethod
    async def get_role_by_name(name: str) -> Optional[Any]:
        prisma = db_manager.client
        return await prisma.role.find_unique(
            where={"name": name},
            include={"rolePermissions": {"include": {"permission": True}}}
        )

    @staticmethod
    async def list_roles() -> List[Any]:
        prisma = db_manager.client
        return await prisma.role.find_many(
            include={"rolePermissions": {"include": {"permission": True}}},
            order={"name": "asc"}
        )

    @staticmethod
    async def assign_permission_to_role(role_id: str, permission_id: str) -> Any:
        prisma = db_manager.client
        return await prisma.rolepermission.upsert(
            where={"roleId_permissionId": {"roleId": role_id, "permissionId": permission_id}},
            data={
                "create": {"roleId": role_id, "permissionId": permission_id},
                "update": {}
            }
        )

    # ==================== USERS ====================

    @staticmethod
    async def create_user(
        username: str,
        display_name: str,
        email: str,
        password: str,
        role_id: str,
        status: str = "ACTIVE"
    ) -> Any:
        prisma = db_manager.client
        hashed = IdentityRepository.hash_password(password)

        return await prisma.user.create(
            data={
                "username": username,
                "displayName": display_name,
                "email": email,
                "passwordHash": hashed,
                "roleId": role_id,
                "status": status
            },
            include={"role": True}
        )

    @staticmethod
    async def get_user(user_id: str) -> Optional[Any]:
        prisma = db_manager.client
        return await prisma.user.find_unique(
            where={"id": user_id},
            include={
                "role": {
                    "include": {
                        "rolePermissions": {"include": {"permission": True}}
                    }
                }
            }
        )

    @staticmethod
    async def get_user_by_username(username: str) -> Optional[Any]:
        prisma = db_manager.client
        return await prisma.user.find_unique(
            where={"username": username},
            include={"role": True}
        )

    @staticmethod
    async def list_users() -> List[Any]:
        prisma = db_manager.client
        return await prisma.user.find_many(
            include={"role": True},
            order={"createdAt": "desc"}
        )

    @staticmethod
    async def update_user(
        user_id: str,
        display_name: Optional[str] = None,
        email: Optional[str] = None,
        role_id: Optional[str] = None,
        status: Optional[str] = None,
        last_activity: Optional[datetime] = None
    ) -> Any:
        prisma = db_manager.client
        update_data: Dict[str, Any] = {}

        if display_name is not None:
            update_data["displayName"] = display_name
        if email is not None:
            update_data["email"] = email
        if role_id is not None:
            update_data["roleId"] = role_id
        if status is not None:
            update_data["status"] = status
        if last_activity is not None:
            update_data["lastActivity"] = last_activity

        return await prisma.user.update(
            where={"id": user_id},
            data=update_data,
            include={"role": True}
        )

identity_repository = IdentityRepository()