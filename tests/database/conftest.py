"Echte isolierte PostgreSQL-Instanz, kein Skip und keine fremden Volumes."

import uuid
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest

from scripts.database.manage import cleanup_test, connect, migrate, prepare, provision
from scripts.infrastructure.manage import Config, compose, load_config
from tests.database.helpers import required_row


@pytest.fixture(scope="session")
def db_config() -> Iterator[Config]:
    config = load_config(overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-" + uuid.uuid4().hex[:12]})
    prepare(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        provision(config)
        migrate(config, "0001_foundation")
        with connect(config) as connection:
            assert required_row(connection.execute("SELECT to_regnamespace('inventory') AS n"))["n"]
            assert not required_row(
                connection.execute("SELECT to_regclass('inventory.servers') AS n")
            )["n"]
        migrate(config)
        with connect(config) as connection:
            users = connection.execute("SELECT count(*) AS count FROM security.users").fetchone()
            assert users is not None and users["count"] == 0
        yield config
    finally:
        cleanup_test(config)


@pytest.fixture
def owner(db_config: Config) -> Iterator[psycopg.Connection[dict[str, Any]]]:
    with connect(db_config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        try:
            yield connection
        finally:
            connection.rollback()
