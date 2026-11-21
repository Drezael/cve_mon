"""Actual PostgreSQL via async Psycopg/SQLAlchemy, real grants and concurrency."""

import asyncio
from pathlib import Path
from uuid import uuid4

import pytest
from cve_common.database.engine import Database
from cve_common.database.sessions import session
from cve_common.database.transactions import transaction
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from tests.services.integration.conftest import Lab

pytestmark = [pytest.mark.services_integration, pytest.mark.security]


async def test_identity_pool_and_read_sessions(service_lab: Lab) -> None:
    database = Database(service_lab.settings())
    database.open()
    try:
        assert await database.ready(2)

        async def read() -> str:
            async with session(database) as s:
                return str((await s.execute(text("SELECT current_user"))).scalar_one())

        assert await asyncio.gather(*(read() for _ in range(12))) == ["api_reader"] * 12
        async with session(database) as s:
            assert not (
                await s.execute(
                    text(
                        "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls "
                        "FROM pg_roles WHERE rolname=current_user"
                    )
                )
            ).scalar_one()
    finally:
        await database.close()
    assert database.engine is None and database.sessions is None


async def test_commit_rollback_and_cancel(service_lab: Lab) -> None:
    database = Database(service_lab.settings("dashboard_admin"))
    database.open()
    scope = "phase06-" + uuid4().hex
    try:
        async with transaction(database) as s:
            await s.execute(
                text("INSERT INTO dashboard.order_versions(scope,version) VALUES (:scope,1)"),
                {"scope": scope},
            )
        for error in (RuntimeError, asyncio.CancelledError):
            with pytest.raises(error):
                async with transaction(database) as s:
                    await s.execute(
                        text("UPDATE dashboard.order_versions SET version=2 WHERE scope=:scope"),
                        {"scope": scope},
                    )
                    raise error()
        async with session(database) as s:
            assert (
                await s.execute(
                    text("SELECT version FROM dashboard.order_versions WHERE scope=:scope"),
                    {"scope": scope},
                )
            ).scalar_one() == 1
        # A read context never commits incidental writes.
        async with session(database) as s:
            await s.execute(
                text("UPDATE dashboard.order_versions SET version=2 WHERE scope=:scope"),
                {"scope": scope},
            )
        async with session(database) as s:
            assert (
                await s.execute(
                    text("SELECT version FROM dashboard.order_versions WHERE scope=:scope"),
                    {"scope": scope},
                )
            ).scalar_one() == 1
    finally:
        await database.close()


@pytest.mark.parametrize(
    "query",
    [
        "INSERT INTO inventory.server_groups(name) VALUES ('forbidden')",
        "CREATE TABLE public.forbidden_table(id int)",
        "SET ROLE postgres_owner",
        "SELECT * FROM security.password_credentials",
    ],
)
async def test_reader_permissions(service_lab: Lab, query: str) -> None:
    database = Database(service_lab.settings())
    database.open()
    try:
        with pytest.raises(DBAPIError):
            async with transaction(database) as s:
                await s.execute(text(query))
        assert await database.ready(2)
    finally:
        await database.close()


async def test_wrong_password_and_unreachable(service_lab: Lab, tmp_path: Path) -> None:
    path = tmp_path / "wrong"
    path.write_text("synthetic-invalid-credential")
    path.chmod(0o600)
    for overrides in ({"password_file": path}, {"hostaddr": "127.0.0.1", "port": 1}):
        database = Database(service_lab.settings(**overrides))
        database.open()
        try:
            assert not await database.ready(0.5)
        finally:
            await database.close()


async def test_pool_exhaustion_and_statement_timeout(service_lab: Lab) -> None:
    database = Database(
        service_lab.settings(pool_size=1, max_overflow=0, pool_timeout=0.1, statement_timeout_ms=50)
    )
    database.open()
    assert database.engine is not None
    try:
        async with database.engine.connect():
            assert not await database.ready(0.3)
        with pytest.raises(SQLAlchemyError):
            async with session(database) as s:
                await s.execute(text("SELECT pg_sleep(.3)"))
        assert await database.ready(2)
    finally:
        await database.close()
