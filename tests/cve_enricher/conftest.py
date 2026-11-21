"""Own native PostgreSQL and runtime identities; no live data or target servers."""

from collections.abc import Iterator
from uuid import uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import compose, load_config
from tests.cve_importer.conftest import Lab


@pytest.fixture(scope="session")
def enrich_lab() -> Iterator[Lab]:
    config = load_config(
        overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-phase16-" + uuid4().hex[:10]}
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
