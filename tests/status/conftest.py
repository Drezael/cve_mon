"""Real isolated TLS PostgreSQL and native session/CSRF API infrastructure."""

from collections.abc import Iterator

import pytest

from scripts.infrastructure.manage import compose
from tests.authentication.integration.conftest import Lab
from tests.inventory_upload.integration.conftest import browser
from tests.inventory_upload.integration.conftest import upload_lab as source_lab

__all__ = ["browser", "source_lab", "upload_lab"]


@pytest.fixture(scope="session")
def upload_lab(source_lab: Lab) -> Iterator[Lab]:
    # Native API fixtures own their lifespans; prevent a second collector racing the same test DB.
    compose(source_lab.config, ["stop", "cve-api"])
    yield source_lab
