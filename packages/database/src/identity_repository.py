import uuid
from typing import List, Optional, Dict, Any
import bcrypt
from datetime import datetime, timezone
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload

from packages.database.src.db_connection import db_manager
from packages.database.src.models import (
    User, Role, Permission, RolePermission, UserStatusEnum
)

class IdentityRepository:
    """SQLAlchemy 2.0 DAL for Users, Roles, Permissions, and RBAC mapping."""

    @staticmethod
    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

    # ==================== PERMISSIONS ====================

    @staticmethod
    async def create_permission(name: str, description: Optional[str] = None) -> Permission:
        async with db_manager.session() as sess:
            res = await sess.execute(select(Permission).where(Permission.name == name))
            perm = res.scalar_one_or_none()
            if not perm:
                perm = Permission(id=str(uuid.uuid4()), name=name, description=description)
                sess.add(perm)
            else:
                perm.description = description
            await sess.flush()
            return perm

    @staticmethod
    async def list_permissions() -> List[Permission]:
        async with db_manager.session() as sess:
            res = await sess.execute(select(Permission).order_by(Permission.name.asc()))
            return list(res.scalars().all())

    # ==================== ROLES ====================

    @staticmethod
    async def create_role(name: str, description: Optional[str] = None) -> Role:
        async with db_manager.session() as sess:
            res = await sess.execute(select(Role).where(Role.name == name))
            role = res.scalar_one_or_none()
            if not role:
                role = Role(id=str(uuid.uuid4()), name=name, description=description)
                sess.add(role)
            else:
                role.description = description
            await sess.flush()
            return role

    @staticmethod
    async def get_role(role_id: str) -> Optional[Role]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(Role)
                .where(Role.id == role_id)
                .options(
                    selectinload(Role.role_permissions).selectinload(RolePermission.permission)
                )
            )
            return res.scalar_one_or_none()

    @staticmethod
    async def get_role_by_name(name: str) -> Optional[Role]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(Role)
                .where(Role.name == name)
                .options(
                    selectinload(Role.role_permissions).selectinload(RolePermission.permission)
                )
            )
            return res.scalar_one_or_none()

    @staticmethod
    async def list_roles() -> List[Role]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(Role)
                .options(
                    selectinload(Role.role_permissions).selectinload(RolePermission.permission)
                )
                .order_by(Role.name.asc())
            )
            return list(res.scalars().all())

    @staticmethod
    async def assign_permission_to_role(role_id: str, permission_id: str) -> RolePermission:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(RolePermission).where(
                    RolePermission.role_id == role_id,
                    RolePermission.permission_id == permission_id
                )
            )
            rp = res.scalar_one_or_none()
            if not rp:
                rp = RolePermission(role_id=role_id, permission_id=permission_id)
                sess.add(rp)
            await sess.flush()
            return rp

    # ==================== USERS ====================

    @staticmethod
    async def create_user(
        username: str,
        display_name: str,
        email: str,
        password: str,
        role_id: str,
        status: str = "ACTIVE"
    ) -> User:
        hashed = IdentityRepository.hash_password(password)
        st_enum = UserStatusEnum(status.upper()) if isinstance(status, str) else status

        async with db_manager.session() as sess:
            user = User(
                id=str(uuid.uuid4()),
                username=username,
                display_name=display_name,
                email=email,
                password_hash=hashed,
                role_id=role_id,
                status=st_enum
            )
            sess.add(user)
            await sess.flush()
            
            # Eager load role
            res = await sess.execute(
                select(User)
                .where(User.id == user.id)
                .options(selectinload(User.role))
            )
            return res.scalar_one()

    @staticmethod
    async def get_user(user_id: str) -> Optional[User]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(User)
                .where(User.id == user_id)
                .options(
                    selectinload(User.role)
                    .selectinload(Role.role_permissions)
                    .selectinload(RolePermission.permission)
                )
            )
            return res.scalar_one_or_none()

    @staticmethod
    async def get_user_by_username(username: str) -> Optional[User]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(User)
                .where(User.username == username)
                .options(selectinload(User.role))
            )
            return res.scalar_one_or_none()

    @staticmethod
    async def list_users() -> List[User]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(User)
                .options(selectinload(User.role))
                .order_by(User.created_at.desc())
            )
            return list(res.scalars().all())

    @staticmethod
    async def update_user(
        user_id: str,
        display_name: Optional[str] = None,
        email: Optional[str] = None,
        role_id: Optional[str] = None,
        status: Optional[str] = None,
        last_activity: Optional[datetime] = None
    ) -> User:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(User).where(User.id == user_id).options(selectinload(User.role))
            )
            user = res.scalar_one_or_none()
            if not user:
                raise ValueError(f"User {user_id} not found.")

            if display_name is not None:
                user.display_name = display_name
            if email is not None:
                user.email = email
            if role_id is not None:
                user.role_id = role_id
            if status is not None:
                user.status = UserStatusEnum(status.upper()) if isinstance(status, str) else status
            if last_activity is not None:
                user.last_activity = last_activity

            await sess.flush()
            return user

identity_repository = IdentityRepository()