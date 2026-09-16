import os
import ssl
from pathlib import Path
from typing import AsyncGenerator
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

# Automatically load .env from project root
ROOT_DIR = Path(__file__).resolve().parents[3]
env_file = ROOT_DIR / ".env"
if env_file.exists():
    load_dotenv(dotenv_path=env_file, override=True)
else:
    load_dotenv(override=True)

Base = declarative_base()

class DatabaseConnectionManager:
    """Enterprise Asynchronous Database Manager using SQLAlchemy 2.0 & asyncpg."""

    def __init__(self):
        self._engine = None
        self._sessionmaker = None
        self._is_connected = False

    def _get_database_url(self) -> str:
        url = os.environ.get("DATABASE_URL", "").strip().strip('"').strip("'")
        if not url:
            raise ValueError(
                "DATABASE_URL is not set in environment or .env file. "
                "Ensure .env exists at project root with DATABASE_URL defined."
            )
        
        # asyncpg requires postgresql+asyncpg://
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)

        # Remove query parameters from string; asyncpg configures SSL via connect_args
        if "?" in url:
            url = url.split("?")[0]
        return url

    async def connect(self):
        if not self._engine:
            url = self._get_database_url()
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

            self._engine = create_async_engine(
                url,
                echo=False,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                connect_args={"ssl": ssl_ctx}
            )
            self._sessionmaker = async_sessionmaker(
                bind=self._engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            self._is_connected = True
        return self._engine

    async def disconnect(self):
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None
            self._is_connected = False

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        if not self._sessionmaker:
            await self.connect()
        async with self._sessionmaker() as sess:
            try:
                yield sess
                await sess.commit()
            except Exception:
                await sess.rollback()
                raise

db_manager = DatabaseConnectionManager()