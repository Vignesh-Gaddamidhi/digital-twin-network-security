import uuid
from typing import List, Optional, Dict, Any, Union
import bcrypt
from datetime import datetime, timezone
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload

from packages.database.src.db_connection import db_manager
from packages.database.src.models import User, Role, Permission, UserStatusEnum

class IdentityRepository:
    """Data Access Layer for Users, Roles, Permissions, and RBAC mapping."""

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
            res = await sess.execute(select(Permission).order_by(Permission.name))
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
                .options(selectinload(Role.permissions))
            )
            return res.scalar_one_or_none()

    @staticmethod
    async def get_role_by_name(name: str) -> Optional[Role]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(Role)
                .where(Role.name == name)
                .options(selectinload(Role.permissions))
            )
            return res.scalar_one_or_none()

    @staticmethod
    async def list_roles() -> List[Role]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(Role)
                .options(selectinload(Role.permissions))
                .order_by(Role.name)
            )
            return list(res.scalars().all())

    @staticmethod
    async def assign_permission_to_role(role_id: str, permission_id: str) -> None:
        async with db_manager.session() as sess:
            role_res = await sess.execute(
                select(Role)
                .where(Role.id == role_id)
                .options(selectinload(Role.permissions))
            )
            role = role_res.scalar_one_or_none()

            perm_res = await sess.execute(select(Permission).where(Permission.id == permission_id))
            perm = perm_res.scalar_one_or_none()

            if role and perm and perm not in role.permissions:
                role.permissions.append(perm)
                await sess.flush()

    # ==================== USERS ====================

    @staticmethod
    async def create_user(
        username: str,
        display_name: str,
        email: str,
        password: str,
        role_id: str,
        status: Union[str, UserStatusEnum] = UserStatusEnum.ACTIVE
    ) -> User:
        hashed = IdentityRepository.hash_password(password)
        if isinstance(status, str):
            status = UserStatusEnum(status.upper())

        async with db_manager.session() as sess:
            user = User(
                id=str(uuid.uuid4()),
                username=username,
                display_name=display_name,
                email=email,
                password_hash=hashed,
                role_id=role_id,
                status=status
            )
            sess.add(user)
            await sess.flush()

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
                    selectinload(User.role).selectinload(Role.permissions)
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
        status: Optional[Union[str, UserStatusEnum]] = None,
        last_activity: Optional[datetime] = None
    ) -> Optional[User]:
        async with db_manager.session() as sess:
            res = await sess.execute(
                select(User)
                .where(User.id == user_id)
                .options(selectinload(User.role))
            )
            user = res.scalar_one_or_none()
            if not user:
                return None

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

    @staticmethod
    async def delete_user(user_id: str) -> bool:
        async with db_manager.session() as sess:
            res = await sess.execute(select(User).where(User.id == user_id))
            user = res.scalar_one_or_none()
            if user:
                await sess.delete(user)
                return True
            return False

identity_repository = IdentityRepository()