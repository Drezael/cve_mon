"""Bounded PostgreSQL engines; no DDL, SET ROLE or implicit authorization."""

import asyncio
from collections.abc import Mapping

from sqlalchemy import URL, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from cve_common.config.secrets import read_secret
from cve_common.config.settings import DatabaseSettings
from cve_common.logging.redaction import register_secret


class Database:
    def __init__(self, settings: DatabaseSettings) -> None:
        self.settings = settings
        self.engine: AsyncEngine | None = None
        self.sessions: async_sessionmaker[AsyncSession] | None = None

    def open(self) -> None:
        if self.engine is not None:
            raise RuntimeError("Database already initialized")
        if not self.settings.ca_file.is_file():
            raise ValueError("Database CA file required")
        secret = read_secret(self.settings.password_file)
        register_secret(secret)
        options: dict[str, object] = {
            "sslmode": "verify-full",
            "gssencmode": "disable",
            "sslrootcert": str(self.settings.ca_file),
            "connect_timeout": self.settings.connect_timeout,
            "options": "-c statement_timeout=" + str(self.settings.statement_timeout_ms),
        }
        # Phase-23 baseline: request-sized dashboard plans compiled 135 JIT functions,
        # spending >1 s compiling each page and exhausting the bounded auth pool.
        # Keep the existing statement/pool limits and authorization transactions.
        if self.settings.username == "api_security":
            options["options"] = str(options["options"]) + " -c jit=off"
        if self.settings.hostaddr:
            options["hostaddr"] = self.settings.hostaddr
        url = URL.create(
            "postgresql+psycopg",
            username=self.settings.username,
            password=secret.get_secret_value(),
            host=self.settings.host,
            port=self.settings.port,
            database=self.settings.database,
        )
        self.engine = create_async_engine(
            url,
            pool_size=self.settings.pool_size,
            max_overflow=self.settings.max_overflow,
            pool_timeout=self.settings.pool_timeout,
            pool_pre_ping=True,
            pool_recycle=300,
            connect_args=options,
            echo=False,
            hide_parameters=True,
        )
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False, autoflush=False)

    async def ready(self, timeout: float) -> bool:
        if self.engine is None:
            return False
        try:
            async with asyncio.timeout(timeout), self.engine.connect() as connection:
                result = await connection.execute(text("SELECT 1"))
                return bool(result.scalar_one() == 1)
        except (Exception, asyncio.CancelledError) as error:
            if isinstance(error, asyncio.CancelledError):
                raise
            return False

    async def close(self) -> None:
        if self.engine is not None:
            await self.engine.dispose()
        self.engine = None
        self.sessions = None


class DatabaseRegistry:
    """Separate, explicitly configured identities; no request-selected role switching."""

    def __init__(self, contexts: Mapping[str, Database]) -> None:
        self.contexts = dict(contexts)

    def get(self, context: str) -> Database:
        return self.contexts[context]
