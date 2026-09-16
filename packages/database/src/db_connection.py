import os
import asyncio
from typing import Optional
from prisma import Prisma

class DatabaseConnectionManager:
    """Manages the lifecycle of Prisma client connections to PostgreSQL."""

    def __init__(self):
        self._prisma: Optional[Prisma] = None
        self._is_connected: bool = False

    async def connect(self) -> Prisma:
        """Establishes connection to the configured PostgreSQL instance."""
        if not self._prisma:
            self._prisma = Prisma(auto_register=True)

        if not self._is_connected:
            await self._prisma.connect()
            self._is_connected = True
        return self._prisma

    async def disconnect(self) -> None:
        """Gracefully disconnects Prisma client from PostgreSQL."""
        if self._prisma and self._is_connected:
            await self._prisma.disconnect()
            self._is_connected = False

    @property
    def client(self) -> Prisma:
        if not self._prisma or not self._is_connected:
            raise RuntimeError("Database is not connected. Call 'await db_manager.connect()' first.")
        return self._prisma

    @property
    def is_connected(self) -> bool:
        return self._is_connected

db_manager = DatabaseConnectionManager()