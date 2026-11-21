"""Technical service fixtures never use normal deployment data."""

import logging
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
from cve_api.factory import create_app
from cve_api.settings import ApiSettings
from cve_common.config.settings import DatabaseSettings, ServiceSettings
from cve_common.lifecycle.resources import Resources


@pytest.fixture(autouse=True)
def preserve_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


@pytest.fixture
def db_settings(tmp_path: Path) -> DatabaseSettings:
    password = tmp_path / "password"
    password.write_text("synthetic-only-secret\n")
    password.chmod(0o600)
    ca = tmp_path / "ca.crt"
    ca.write_text("unit-only-no-connection")
    return DatabaseSettings(
        host="cve-postgres", username="api_reader", password_file=password, ca_file=ca
    )


@pytest.fixture
def api_settings(db_settings: DatabaseSettings) -> ApiSettings:
    return ApiSettings(app_env="test", database=db_settings)


def no_dependencies(settings: ApiSettings) -> Resources:
    return Resources(ServiceSettings(service_name=settings.service_name, app_env="test"))


@pytest.fixture
async def client(api_settings: ApiSettings) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(api_settings, resource_factory=no_dependencies)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://cve-api",
        ) as current,
    ):
        yield current
