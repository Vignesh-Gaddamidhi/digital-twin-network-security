import os
import ssl
import asyncpg
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from packages.database.src.models import Base

# Ensure .env is always loaded from repository root
try:
    from dotenv import load_dotenv
    root_env = Path(__file__).resolve().parents[3] / ".env"
    if root_env.exists():
        load_dotenv(dotenv_path=root_env, override=True)
    else:
        load_dotenv(override=True)
except ImportError:
    pass

class DatabaseManager:
    def __init__(self):
        self._pool: Optional[asyncpg.Pool] = None
        self._engine = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None

    @property
    def is_connected(self) -> bool:
        return self._pool is not None or self._engine is not None

    @property
    def engine(self):
        return self._engine

    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        ssl_mode = os.getenv("DATABASE_SSL", "").lower()
        database_url = os.getenv("DATABASE_URL", "")
        
        if "sslmode=require" in database_url or "sslmode=verify-full" in database_url or ssl_mode in ("require", "true", "1"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

    def _get_sqlalchemy_url(self) -> str:
        database_url = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/cybertwin")
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif database_url.startswith("postgresql://") and not database_url.startswith("postgresql+asyncpg://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        
        if "?" in database_url:
            database_url = database_url.split("?")[0]
        return database_url

    async def connect(self):
        database_url = os.getenv("DATABASE_URL", "")
        ssl_context = self._get_ssl_context()

        # 1. Initialize asyncpg Pool
        if self._pool is None:
            try:
                if database_url:
                    clean_dsn = database_url.split("?")[0]
                    if clean_dsn.startswith("postgresql+asyncpg://"):
                        clean_dsn = clean_dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
                    if ssl_context:
                        self._pool = await asyncpg.create_pool(
                            dsn=clean_dsn,
                            ssl=ssl_context,
                            min_size=1,
                            max_size=10,
                            timeout=5.0
                        )
                    else:
                        self._pool = await asyncpg.create_pool(
                            dsn=clean_dsn,
                            min_size=1,
                            max_size=10,
                            timeout=5.0
                        )
                else:
                    user = os.getenv("DATABASE_USER", "postgres")
                    password = os.getenv("DATABASE_PASSWORD", "postgres")
                    database = os.getenv("DATABASE_NAME", "digital_twin_security")
                    host = os.getenv("DATABASE_HOST", "localhost")
                    port = int(os.getenv("DATABASE_PORT", "5432"))

                    self._pool = await asyncpg.create_pool(
                        user=user,
                        password=password,
                        database=database,
                        host=host,
                        port=port,
                        ssl=ssl_context,
                        min_size=1,
                        max_size=10,
                        timeout=5.0
                    )
            except Exception as e:
                print(f"[WARN] asyncpg pool initialization fallback: {e}")

        # 2. Initialize SQLAlchemy Async Engine & Sessionmaker
        if self._engine is None:
            sqla_url = self._get_sqlalchemy_url()
            connect_args = {}
            if ssl_context:
                connect_args["ssl"] = ssl_context

            try:
                self._engine = create_async_engine(
                    sqla_url,
                    connect_args=connect_args,
                    pool_size=10,
                    max_overflow=5,
                    pool_pre_ping=True
                )
                self._session_factory = async_sessionmaker(
                    bind=self._engine,
                    class_=AsyncSession,
                    expire_on_commit=False
                )
            except Exception as e:
                print(f"[WARN] SQLAlchemy engine initialization fallback: {e}")

        return self

    async def disconnect(self):
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
        self._session_factory = None

    @asynccontextmanager
    async def session(self):
        if self._session_factory is None:
            await self.connect()
        if self._session_factory is None:
            raise RuntimeError("DatabaseManager failed to create SQLAlchemy session factory.")
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    @asynccontextmanager
    async def begin(self):
        """Context manager delegating to SQLAlchemy engine.begin() for schema operations."""
        if self._engine is None:
            await self.connect()
        if self._engine is None:
            raise RuntimeError("DatabaseManager has no active SQLAlchemy engine.")
        async with self._engine.begin() as conn:
            yield conn

db_manager = DatabaseManager()