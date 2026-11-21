"Real PostgreSQL, MFA, HTTPS deployment and isolated users; no production writes."

from typing import Any
from uuid import uuid4

from tests.authentication.integration.conftest import Browser
from tests.authentication.integration.conftest import auth_lab as auth_lab
from tests.authentication.integration.conftest import browser as browser
from tests.authorization.integration.conftest import Actor, actor, fresh

__all__ = ["auth_lab", "browser", "actor", "Actor", "send", "create_server", "create_group"]


async def send(
    browser: Browser,
    person: Actor,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    match: str | None = None,
    *,
    reauth: bool = True,
) -> Any:
    if method != "GET" and reauth:
        fresh(browser, person)
    headers = {"cookie": "__Host-cve-session=" + person.cookie, "x-csrf-token": person.csrf}
    if match is not None:
        headers["if-match"] = match
    return await browser.client.request(
        method, "/api/v1/dashboard/" + path, json=body, headers=headers
    )


async def create_server(browser: Browser, person: Actor, **extra: Any) -> dict[str, Any]:
    result = await send(
        browser,
        person,
        "POST",
        "admin/servers",
        {"display_name": "host-" + uuid4().hex[:8], "request_id": str(uuid4()), **extra},
    )
    assert result.status_code == 201, result.text
    return dict(result.json())


async def create_group(browser: Browser, person: Actor, **extra: Any) -> dict[str, Any]:
    state = await send(browser, person, "GET", "groups")
    name = "group-" + uuid4().hex[:8]
    result = await send(
        browser,
        person,
        "POST",
        "groups",
        {"name": name, "version": state.json()["version"], **extra},
        reauth=False,
    )
    assert result.status_code == 201, result.text
    group = next(g for g in result.json()["items"] if g["name"] == extra.get("name", name))
    return dict(group) | {"version": result.json()["version"]}


async def assign_groups(browser: Browser, person: Actor, server: str, groups: list[str]) -> Any:
    state = await send(browser, person, "GET", "groups")
    return await send(
        browser,
        person,
        "PUT",
        f"servers/{server}/groups",
        {"group_ids": groups, "version": state.json()["version"]},
        reauth=False,
    )
