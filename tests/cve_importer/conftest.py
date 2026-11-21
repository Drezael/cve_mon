"""Dedicated PostgreSQL with real roles; no shared development rows or target servers."""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from cve_common.config.settings import DatabaseSettings

from scripts.database import manage as db
from scripts.infrastructure.manage import Config, compose, load_config


@dataclass
class Lab:
    config: Config

    def settings(self, role: str = "importer") -> DatabaseSettings:
        return DatabaseSettings(
            host="cve-postgres",
            hostaddr=db.address(self.config),
            username=role,
            password_file=db.secret_file(self.config, role),
            ca_file=db.workdir(self.config) / "tls/ca.crt",
            pool_size=5,
            statement_timeout_ms=30000,
        )

    def owner(self) -> psycopg.Connection[dict[str, Any]]:
        c = db.connect(self.config, "cve_migrator")
        c.execute("SET ROLE postgres_owner")
        return c


@pytest.fixture(scope="session")
def import_lab() -> Iterator[Lab]:
    config = load_config(
        overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-phase15-" + uuid4().hex[:10]}
    )
    db.prepare(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(config)
        db.migrate(config)
        db.migrate(config)
        yield Lab(config)
    finally:
        db.cleanup_test(config)
