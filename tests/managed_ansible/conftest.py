"""Isolated inventory/API database and browser for managed SSH vault tests."""

import asyncio
import secrets
from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import compose, generate_certificates
from scripts.security import manage as auth
from scripts.services import manage as api
from tests.authentication.integration.conftest import Lab
from tests.configuration import load_test_config
from tests.inventory_upload.integration.conftest import browser

__all__ = ["browser", "upload_lab"]


@pytest.fixture(scope="session")
def upload_lab() -> Iterator[Lab]:
    project = "cve-db-test-personal-vault-" + uuid4().hex[:10]
    config = load_test_config(
        overrides={
            "COMPOSE_PROJECT_NAME": project,
            "TLS_DIR": ".runtime/managed-vault-tests/" + project + "/pki",
            "STATUS_COLLECTOR_PAUSED": "true",
        }
    )
    db.prepare(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(config)
        db.migrate(config)
        db.migrate(config)
        generate_certificates(config, fixtures=True)
        api.prepare(config)
        password = secrets.token_urlsafe(24)
        user = UUID(
            asyncio.run(
                auth.bootstrap(config, "vault-initial-admin", "initial@example.test", password)
            )
        )
        yield Lab(config, password, user)
    finally:
        db.cleanup_test(config)
