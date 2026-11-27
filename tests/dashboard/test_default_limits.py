"""A fresh real browser can log in and open three tabs using unchanged deployment limits."""

import os
import subprocess
from collections.abc import Iterator

import pytest

from scripts.dashboard.manage import activate, node
from scripts.infrastructure.policy import INTERNAL_DEFAULTS
from scripts.security.manage import origin
from tests.authentication.integration.conftest import Lab
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser, browser, isolated_upload_lab

__all__ = ["browser"]
pytestmark = pytest.mark.dashboard


@pytest.fixture(scope="module")
def upload_lab() -> Iterator[Lab]:
    yield from isolated_upload_lab(
        {key: INTERNAL_DEFAULTS[key] for key in ("WEB_RATE", "UPLOAD_RATE", "RATE_BURST")}
    )


async def test_fresh_login_reload_and_tabs_with_default_limits(browser: Browser) -> None:
    person = await actor(browser, ("security_analyst",))
    with browser.lab.owner() as connection:
        connection.execute(
            "UPDATE security.instance_preferences SET default_locale='de',version=version+1"
        )
    config = browser.lab.config
    activate(config)
    binary = node(config.root)
    environment = {
        **os.environ,
        "PATH": str(binary) + os.pathsep + os.environ.get("PATH", ""),
        "PLAYWRIGHT_BROWSERS_PATH": str(config.root / ".runtime/playwright"),
        "CVE_E2E_URL": origin(config),
        "CVE_E2E_USER": person.name,
        "CVE_E2E_PASSWORD": person.password,
    }
    result = subprocess.run(
        [str(binary / "node"), "tests/browser/default-limits.mjs"],
        cwd=config.root / "services/dashboard",
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
