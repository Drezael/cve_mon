"""Real PostgreSQL language precedence, account isolation and first-start environment semantics."""

import pytest
from cve_api.localization import bootstrap

from scripts.database import manage as db
from tests.authorization.integration.conftest import Actor, actor
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.dashboard_administration
PERSONAL = "/api/v1/dashboard/me/locale"
ADMIN = "/api/v1/dashboard/administration/localization"
PUBLIC = "/api/v1/dashboard/localization"


def headers(person: Actor, version: int | None = None) -> dict[str, str]:
    values = {"cookie": "__Host-cve-session=" + person.cookie, "x-csrf-token": person.csrf}
    if version is not None:
        values["if-match"] = '"' + str(version) + '"'
    return values


async def test_initial_default_environment_and_saved_value_take_precedence(
    browser: Browser,
) -> None:
    # This fixture is an isolated PostgreSQL project; simulate an empty first-start settings table.
    for configured, wanted in [(None, "en"), ("", "en"), ("de", "de"), ("en", "en")]:
        with browser.lab.owner() as s:
            s.execute("DELETE FROM security.instance_preferences")
        values = {} if configured is None else {"CVE_DEFAULT_LANGUAGE": configured}
        await bootstrap(browser.service, values)
        before = (await browser.client.get(PUBLIC)).json()
        assert before == {"default_locale": wanted}
        for changed in ["de", "en", "unsupported"]:
            await bootstrap(browser.service, {"CVE_DEFAULT_LANGUAGE": changed})
            assert (await browser.client.get(PUBLIC)).json() == before
        with browser.lab.owner() as s:
            row = s.execute("SELECT version,origin FROM security.instance_preferences").fetchone()
            assert row == {"version": 1, "origin": "environment"}
            audit = s.execute(
                "SELECT technical_principal_id FROM security.audit_log WHERE "
                "action='locale.default.initialized' ORDER BY occurred_at DESC LIMIT 1"
            ).fetchone()
            assert audit and audit["technical_principal_id"]
    with browser.lab.owner() as s:
        s.execute("DELETE FROM security.instance_preferences")
    with pytest.raises(Exception, match="Initial default language"):
        await bootstrap(browser.service, {"CVE_DEFAULT_LANGUAGE": "fr"})
    await bootstrap(browser.service, {})


async def test_account_preferences_are_private_versioned_and_require_csrf(browser: Browser) -> None:
    first = await actor(browser, ("viewer",))
    other = await actor(browser, ())
    initial = await browser.client.get(PERSONAL, headers=headers(first))
    assert initial.status_code == 200
    assert initial.json() == {
        "locale": None,
        "default_locale": "en",
        "effective_locale": "en",
        "version": 0,
    }
    missing = await browser.client.put(PERSONAL, headers=headers(first), json={"locale": "de"})
    assert missing.status_code == 428
    invalid_csrf = headers(first, 0) | {"x-csrf-token": "wrong"}
    assert (
        await browser.client.put(PERSONAL, headers=invalid_csrf, json={"locale": "de"})
    ).status_code == 403
    saved = await browser.client.put(PERSONAL, headers=headers(first, 0), json={"locale": "de"})
    assert saved.status_code == 200, saved.text
    assert saved.headers["etag"] == '"1"' and saved.json()["effective_locale"] == "de"
    assert (await browser.client.get(PERSONAL, headers=headers(other))).json()["locale"] is None
    conflict = await browser.client.put(PERSONAL, headers=headers(first, 0), json={"locale": "en"})
    assert conflict.status_code == 412
    for body in [{"locale": "fr"}, {"locale": "en", "user_id": str(first.id)}]:
        denied = await browser.client.put(PERSONAL, headers=headers(other, 0), json=body)
        assert denied.status_code == 422
    assert (await browser.client.get(PERSONAL, headers=headers(first))).json()["locale"] == "de"
    with browser.lab.owner() as s:
        count = s.execute(
            "SELECT count(*) n FROM security.audit_log WHERE actor_user_id=%s "
            "AND action='locale.account.updated'",
            (first.id,),
        ).fetchone()
        assert count == {"n": 1}
    with (
        db.connect(browser.lab.config, "api_reader") as s,
        pytest.raises(Exception, match="permission denied"),
    ):
        s.execute("SELECT * FROM security.user_preferences")


async def test_instance_admin_default_applies_only_to_inheriting_accounts(browser: Browser) -> None:
    administrator = await actor(browser)
    viewer = await actor(browser, ("viewer",))
    user_admin = await actor(browser, ("user_admin",))
    own = await browser.client.put(
        PERSONAL, headers=headers(administrator, 0), json={"locale": "en"}
    )
    assert own.status_code == 200
    for person in [viewer, user_admin]:
        assert (await browser.client.get(ADMIN, headers=headers(person))).status_code == 403
        assert (
            await browser.client.put(
                ADMIN, headers=headers(person, 1), json={"default_locale": "de"}
            )
        ).status_code == 403
    current = await browser.client.get(ADMIN, headers=headers(administrator))
    saved = await browser.client.put(
        ADMIN,
        headers=headers(administrator, current.json()["version"]),
        json={"default_locale": "de"},
    )
    assert saved.status_code == 200, saved.text
    assert (await browser.client.get(PERSONAL, headers=headers(viewer))).json()[
        "effective_locale"
    ] == "de"
    assert (await browser.client.get(PERSONAL, headers=headers(administrator))).json()[
        "effective_locale"
    ] == "en"
    # Re-run the real startup path with a conflicting Compose value, including an invalid one.
    await bootstrap(browser.service, {"CVE_DEFAULT_LANGUAGE": "en"})
    await bootstrap(browser.service, {"CVE_DEFAULT_LANGUAGE": "invalid-after-initialization"})
    assert (await browser.client.get(PUBLIC)).json()["default_locale"] == "de"
    repeated = await browser.client.put(
        ADMIN,
        headers=headers(administrator, current.json()["version"]),
        json={"default_locale": "en"},
    )
    assert repeated.status_code == 412
    reset = await browser.client.put(
        PERSONAL, headers=headers(administrator, own.json()["version"]), json={"locale": None}
    )
    assert reset.status_code == 200 and reset.json()["effective_locale"] == "de"
    # Restore the isolated fixture default for other tests.
    await browser.client.put(
        ADMIN,
        headers=headers(administrator, saved.json()["version"]),
        json={"default_locale": "en"},
    )
