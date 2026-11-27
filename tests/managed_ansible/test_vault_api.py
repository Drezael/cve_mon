"""Native vault prerequisite, ownership, rotation and secret-free public responses."""

import json
import secrets
from pathlib import Path

import pytest
from cve_common.user_vault import UserVaultKeyring, decrypt_credentials

from scripts.database import manage as db
from tests.authorization.integration.conftest import actor, call
from tests.inventory_upload.integration.conftest import Browser
from tests.server_administration.integration.conftest import create_server

pytestmark = pytest.mark.automation
VAULT = "me/ansible-vault"


async def test_vault_requires_reauth_csrf_and_never_returns_secrets(browser: Browser) -> None:
    person = await actor(browser, ("user",))
    password = secrets.token_urlsafe(24)
    body = {"password": password, "password_confirmation": password}
    assert (await call(browser, person, "GET", VAULT)).json() == {"configured": False}
    denied = await call(browser, person, "PUT", VAULT, body, reauth=False)
    assert denied.status_code == 403, denied.text
    no_csrf = await browser.client.put("/api/v1/dashboard/" + VAULT, json=body)
    assert no_csrf.status_code == 403
    for invalid in [body | {"user_id": str(person.id)}, body | {"password_confirmation": "x" * 20}]:
        result = await call(browser, person, "PUT", VAULT, invalid)
        assert result.status_code == 422
        assert password not in result.text
    saved = await call(browser, person, "PUT", VAULT, body)
    assert saved.status_code == 200, saved.text
    assert saved.json() == {"configured": True}
    state = await call(browser, person, "GET", VAULT)
    assert state.json() == {"configured": True}
    other = await actor(browser, ("user",))
    assert (await call(browser, other, "GET", VAULT)).json() == {"configured": False}
    assert (await call(browser, other, "GET", VAULT + "/" + str(person.id))).status_code == 404
    for role in ["api_reader", "dashboard_admin", "notification"]:
        with (
            db.connect(browser.lab.config, role) as s,
            pytest.raises(Exception, match="permission denied"),
        ):
            s.execute("SELECT * FROM security.ansible_vaults")
    with db.connect(browser.lab.config, "ansible_worker") as s:
        assert s.execute(
            "SELECT user_id,key_id,runtime_envelope FROM security.ansible_vaults"
        ).fetchone()
        with pytest.raises(Exception, match="permission denied"):
            s.execute("SELECT password_envelope FROM security.ansible_vaults")


async def test_credentials_require_own_vault_and_survive_password_rotation(
    browser: Browser,
) -> None:
    person = await actor(browser, ("user",))
    server = await create_server(browser, person)
    path = "servers/" + server["id"] + "/ansible"
    ssh_password = secrets.token_urlsafe(24)
    body = {
        "version": 0,
        "host": "192.0.2.22",
        "username": "collector",
        "auth_method": "password",
        "password": ssh_password,
    }
    denied = await call(browser, person, "PUT", path, body, reauth=False)
    assert denied.status_code == 409, denied.text
    password = secrets.token_urlsafe(24)
    result = await call(
        browser,
        person,
        "PUT",
        VAULT,
        {
            "password": password,
            "password_confirmation": password,
        },
    )
    assert result.status_code == 200, result.text
    result = await call(browser, person, "PUT", path, body, reauth=False)
    assert result.status_code == 200, result.text
    state = await call(browser, person, "GET", path)
    assert state.json()["vault_configured"] and state.json()["editable"]
    assert ssh_password not in state.text and "ciphertext" not in state.text
    with browser.lab.owner() as s:
        before = s.execute(
            "SELECT ciphertext FROM inventory.ansible_profiles WHERE server_id=%s", (server["id"],)
        ).fetchone()["ciphertext"]
    # A metadata edit must preserve the opaque encrypted credential.
    edit = await call(
        browser,
        person,
        "PUT",
        path,
        {**{k: v for k, v in body.items() if k != "password"}, "version": 1},
        reauth=False,
    )
    assert edit.status_code == 200, edit.text
    new_password = secrets.token_urlsafe(24)
    wrong = await call(
        browser,
        person,
        "PUT",
        VAULT,
        {
            "password": new_password,
            "password_confirmation": new_password,
            "current_password": "incorrect-vault-fixture-only",  # pragma: allowlist secret
        },
    )
    assert wrong.status_code == 422
    rotated = await call(
        browser,
        person,
        "PUT",
        VAULT,
        {
            "password": new_password,
            "password_confirmation": new_password,
            "current_password": password,
        },
    )
    assert rotated.status_code == 200, rotated.text
    with browser.lab.owner() as s:
        vault = s.execute(
            "SELECT * FROM security.ansible_vaults WHERE user_id=%s", (person.id,)
        ).fetchone()
        profile = s.execute(
            "SELECT * FROM inventory.ansible_profiles WHERE server_id=%s", (server["id"],)
        ).fetchone()
        assert bytes(profile["ciphertext"]) == bytes(before)
        assert ssh_password not in json.dumps(profile, default=str)
    ring = UserVaultKeyring(Path(browser.service.settings.keyring_file).with_name("ssh-keys.json"))
    assert decrypt_credentials(
        ring.runtime_key(person.id, vault),
        person.id,
        profile["server_id"],
        bytes(profile["ciphertext"]),
    ) == {"password": ssh_password}
    other = await actor(browser)
    other_password = secrets.token_urlsafe(24)
    assert (
        await call(
            browser,
            other,
            "PUT",
            VAULT,
            {
                "password": other_password,
                "password_confirmation": other_password,
            },
        )
    ).status_code == 200
    denied = await call(browser, other, "PUT", path, body, reauth=False)
    assert denied.status_code == 403
    assert not (await call(browser, other, "GET", path)).json()["editable"]


async def test_legacy_profile_cannot_run_or_silently_import_old_secrets(browser: Browser) -> None:
    person = await actor(browser, ("user",))
    server = await create_server(browser, person)
    path = "servers/" + server["id"] + "/ansible"
    with browser.lab.owner() as s:
        s.execute(
            "INSERT INTO inventory.ansible_profiles(server_id,owner_id,host,port,username,"
            "auth_method,key_id,ciphertext) "
            "VALUES(%s,%s,'192.0.2.23',22,'collector','password','legacy',%s)",
            (server["id"], person.id, b"opaque-legacy-encrypted-fixture"),
        )
    state = await call(browser, person, "GET", path)
    assert state.status_code == 200
    assert not state.json()["credentials_configured"]
    assert (await call(browser, person, "POST", path + "/probe", reauth=False)).status_code == 409
    password = secrets.token_urlsafe(24)
    assert (
        await call(
            browser,
            person,
            "PUT",
            VAULT,
            {
                "password": password,
                "password_confirmation": password,
            },
        )
    ).status_code == 200
    config = {
        "version": 1,
        "host": "192.0.2.23",
        "username": "collector",
        "auth_method": "password",
    }
    assert (await call(browser, person, "PUT", path, config, reauth=False)).status_code == 422
    saved = await call(
        browser, person, "PUT", path, config | {"password": secrets.token_urlsafe(24)}, reauth=False
    )
    assert saved.status_code == 200, saved.text
    assert (await call(browser, person, "GET", path)).json()["credentials_configured"]


async def test_stale_profile_write_preserves_jobs_credentials_and_audit(browser: Browser) -> None:
    person = await actor(browser, ("user",))
    server = await create_server(browser, person)
    path = "servers/" + server["id"] + "/ansible"
    password = secrets.token_urlsafe(24)
    saved = await call(
        browser, person, "PUT", VAULT, {"password": password, "password_confirmation": password}
    )
    assert saved.status_code == 200, saved.text
    body = {
        "version": 0,
        "host": "192.0.2.25",
        "username": "collector",
        "auth_method": "password",
        "password": secrets.token_urlsafe(24),
    }
    saved = await call(browser, person, "PUT", path, body, reauth=False)
    assert saved.status_code == 200, saved.text
    first = await call(
        browser, person, "PUT", path, body | {"version": 1, "host": "192.0.2.26"}, reauth=False
    )
    assert first.status_code == 200, first.text
    probe = await call(browser, person, "POST", path + "/probe", reauth=False)
    assert probe.status_code == 202, probe.text
    with browser.lab.owner() as s:
        before = s.execute(
            "SELECT version,ciphertext,host FROM inventory.ansible_profiles WHERE server_id=%s",
            (server["id"],),
        ).fetchone()
        job = s.execute(
            "SELECT j.status FROM automation.jobs j JOIN inventory.ansible_runs r "
            "ON r.job_id=j.id WHERE r.id=%s",
            (probe.json()["run_id"],),
        ).fetchone()
    stale = await call(browser, person, "PUT", path, body | {"version": 1}, reauth=False)
    assert stale.status_code == 412, stale.text
    with browser.lab.owner() as s:
        assert (
            s.execute(
                "SELECT version,ciphertext,host FROM inventory.ansible_profiles WHERE server_id=%s",
                (server["id"],),
            ).fetchone()
            == before
        )
        assert (
            s.execute(
                "SELECT j.status FROM automation.jobs j JOIN inventory.ansible_runs r "
                "ON r.job_id=j.id WHERE r.id=%s",
                (probe.json()["run_id"],),
            ).fetchone()
            == job
        )
        events = s.execute(
            "SELECT metadata FROM security.audit_log WHERE action='ansible.configured' "
            "AND object_id=%s ORDER BY occurred_at",
            (server["id"],),
        ).fetchall()
        assert len(events) == 2
        assert all(set(row["metadata"]) == {"profile_version"} for row in events)


async def test_failed_vault_password_consumes_reauth_and_persistent_admission(
    browser: Browser,
) -> None:
    person = await actor(browser, ("user",))
    password = secrets.token_urlsafe(24)
    body = {"password": password, "password_confirmation": password}
    assert (await call(browser, person, "PUT", VAULT, body)).status_code == 200
    bad = body | {"current_password": secrets.token_urlsafe(24)}
    failed = await call(browser, person, "PUT", VAULT, bad)
    assert failed.status_code == 422, failed.text
    # Failed KDF verification must not roll the consumed reauthentication back.
    repeat = await call(browser, person, "PUT", VAULT, bad, reauth=False)
    assert repeat.status_code == 403, repeat.text
    for _ in range(3):
        assert (await call(browser, person, "PUT", VAULT, bad)).status_code == 422
    limited = await call(browser, person, "PUT", VAULT, bad)
    assert limited.status_code == 429, limited.text


async def test_runtime_rotation_is_resumable_and_old_backup_envelopes_remain_readable(
    browser: Browser,
    tmp_path: Path,
) -> None:
    from scripts.automation_executor.rotation import retire, rewrap, stage, verify

    person = await actor(browser, ("user",))
    password = secrets.token_urlsafe(24)
    response = await call(
        browser, person, "PUT", VAULT, {"password": password, "password_confirmation": password}
    )
    assert response.status_code == 200, response.text
    path = Path(browser.service.settings.keyring_file).with_name("ssh-keys.json")
    original = UserVaultKeyring(path)
    with browser.lab.owner() as s:
        backup = s.execute(
            "SELECT * FROM security.ansible_vaults WHERE user_id=%s", (person.id,)
        ).fetchone()
    key = original.runtime_key(person.id, backup)
    stage(browser.lab.config, "review-rotation")
    ring = UserVaultKeyring(path)
    assert ring.runtime_key(person.id, backup) == key
    assert rewrap(browser.lab.config, batch_size=2)["verified"] >= 1
    assert rewrap(browser.lab.config, batch_size=2) == verify(browser.lab.config)
    with browser.lab.owner() as s:
        fresh = s.execute(
            "SELECT * FROM security.ansible_vaults WHERE user_id=%s", (person.id,)
        ).fetchone()
    assert fresh["key_id"] == ring.active == "review-rotation"
    assert ring.runtime_key(person.id, fresh) == key
    assert bytes(fresh["password_envelope"]) == bytes(backup["password_envelope"])
    # Historical backups retain their original envelope and need the archived old keyring.
    assert original.runtime_key(person.id, backup) == key
    archive = tmp_path / "archived-keyring.json"
    retire(browser.lab.config, original.active, archive)
    retired = UserVaultKeyring(path)
    assert original.active not in retired.keys
    assert UserVaultKeyring(archive).runtime_key(person.id, backup) == key
    assert retired.runtime_key(person.id, fresh) == key
