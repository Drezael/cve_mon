"""Real Nginx HTTPS, scoped API restarts and protected administration routes."""

import pytest

from scripts.infrastructure.manage import compose
from scripts.services import manage as api
from tests.authentication.integration.conftest import Browser
from tests.infrastructure.client import request

from .conftest import actor

pytestmark = [pytest.mark.authorization, pytest.mark.security]


async def test_real_https_admin_user_admin_and_viewer_boundaries(browser: Browser) -> None:
    admin = await actor(browser)
    manager = await actor(browser, ("user_admin",))
    viewer = await actor(browser, ("viewer",))
    for person, status in ((admin, 200), (manager, 200), (viewer, 403)):
        response = request(
            browser.lab.config,
            path="/api/v1/dashboard/admin/users",
            headers={
                "Cookie": "__Host-cve-session=" + person.cookie,
                "X-User-ID": str(admin.id),
                "X-Role": "admin",
            },
        )
        assert response.status == status, response.body
        if person == manager:
            assert str(admin.id) not in response.body
    assert request(browser.lab.config, path="/api/v1/dashboard/admin/users").status == 401
    assert (
        request(
            browser.lab.config, domain="api.example.test", path="/api/v1/dashboard/admin/users"
        ).status
        == 403
    )
    for path in ("/api/v1/dashboard/admin/servers", "/api/v1/dashboard/admin/groups"):
        assert request(browser.lab.config, path=path).status == 401
    assert request(browser.lab.config, path="/api/v1/inventories").status in (403, 404, 503)


async def test_permissions_survive_restart_and_fail_closed_during_database_outage(
    browser: Browser,
) -> None:
    admin = await actor(browser)
    cfg = browser.lab.config
    headers = {"Cookie": "__Host-cve-session=" + admin.cookie}
    assert request(cfg, path="/api/v1/dashboard/admin/users", headers=headers).status == 200
    compose(cfg, ["restart", "cve-api"])
    compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "45", "cve-api"])
    assert request(cfg, path="/api/v1/dashboard/admin/users", headers=headers).status == 200
    try:
        compose(cfg, ["stop", "cve-postgres"])
        assert (
            request(cfg, path="/api/v1/dashboard/admin/users", headers=headers, timeout=15).status
            == 503
        )
        assert api.probe(cfg, "/health/live")["status"] == "alive"
    finally:
        compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
    assert request(cfg, path="/api/v1/dashboard/admin/users", headers=headers).status == 200
    container = api.container(cfg)
    assert not container["HostConfig"]["PortBindings"] and container["HostConfig"]["ReadonlyRootfs"]


async def test_technical_bearer_and_untrusted_backend_headers_confer_no_identity(
    browser: Browser,
) -> None:
    browser.client.cookies.clear()
    result = await browser.client.get(
        "/api/v1/dashboard/admin/users",
        headers={
            "authorization": "Bearer invented-machine-token",
            "x-user-id": "forged",
            "x-role": "admin",
        },
    )
    assert result.status_code == 401
    for header in ("x-cve-auth-gateway", "origin"):
        saved = browser.client.headers.pop(header)
        response = await browser.client.post(
            "/api/v1/dashboard/admin/users", json={"username": "forged"}
        )
        browser.client.headers[header] = saved
        assert response.status_code == 403
