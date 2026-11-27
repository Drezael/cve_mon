"""Owner-scoped encrypted settings and n8n-gated requests on native PostgreSQL."""

import secrets
from pathlib import Path
from typing import Any

import pytest

from tests.authorization.integration.conftest import actor, call
from tests.inventory_upload.integration.conftest import Browser
from tests.managed_ansible.test_ssh_execution import ssh_target
from tests.server_administration.integration.conftest import create_server

__all__ = ["ssh_target"]
pytestmark = pytest.mark.findings


async def test_profile_and_n8n_request(browser: Browser) -> None:
    person = await actor(browser)
    server = await create_server(browser, person)
    vault_password = secrets.token_urlsafe(24)
    vault = await call(
        browser,
        person,
        "PUT",
        "me/ansible-vault",
        {
            "password": vault_password,
            "password_confirmation": vault_password,
        },
    )
    assert vault.status_code == 200, vault.text
    client = browser.client
    path = "/api/v1/dashboard/servers/" + str(server["id"]) + "/ansible"
    headers = {"x-csrf-token": browser.csrf}
    fixture_password = secrets.token_urlsafe(24)
    body = {
        "version": 0,
        "host": "192.168.88.99",
        "port": 22,
        "username": "collector",
        "auth_method": "password",
        "password": fixture_password,
        "interval_seconds": 300,
        "enabled": True,
    }
    response = await client.put(path, json=body, headers=headers)
    assert response.status_code == 200, response.text
    response = await client.get(path)
    assert response.status_code == 200, response.text
    assert fixture_password not in response.text
    assert response.json()["profile"]["interval_seconds"] == 300
    response = await client.post(path + "/collect", headers=headers)
    assert response.status_code == 409, response.text
    response = await client.post(path + "/probe", headers=headers)
    assert response.status_code == 202, response.text
    with browser.lab.owner() as session:
        run = session.execute(
            (
                "SELECT r.*,j.payload,j.status AS job_status FROM inventory.ansibl"
                "e_runs r JOIN automation.jobs j ON j.id=r.job_id WHERE r.id=%s"
            ),
            (response.json()["run_id"],),
        ).fetchone()
        assert set(run["payload"]) == {"run_id"}
        assert run["action"] == "probe"
        assert run["job_status"] in ("queued", "pending")
        assert session.execute(
            "SELECT 1 FROM automation.workflow_requests WHERE job_id=%s", (run["job_id"],)
        ).fetchone()

    with browser.lab.owner() as session:
        version = session.execute(
            "SELECT version FROM inventory.servers WHERE id=%s", (server["id"],)
        ).fetchone()["version"]
    removed = await client.delete(
        path.removesuffix("/ansible"), headers={**headers, "if-match": f'"{version}"'}
    )
    assert removed.status_code == 204, removed.text


@pytest.mark.parametrize("method", ["password", "key", "encrypted-key"])
async def test_real_managed_run_publishes_inventory_only_after_n8n(
    browser: Browser, ssh_target: dict[str, Any], tmp_path: Path, method: str
) -> None:
    import asyncio
    import base64
    import hashlib
    from uuid import uuid4

    from cve_automation.service import Request, Service, Settings
    from cve_common.database.engine import Database
    from cve_common.jobs.execution import ExecutionContext
    from cve_common.jobs.repository import JobRepository

    from scripts.database import manage as db
    from tests.inventory_processor.test_processing import drain

    person = await actor(browser)
    server = await create_server(browser, person)
    vault_password = secrets.token_urlsafe(24)
    vault = await call(
        browser,
        person,
        "PUT",
        "me/ansible-vault",
        {
            "password": vault_password,
            "password_confirmation": vault_password,
        },
    )
    assert vault.status_code == 200, vault.text
    client = browser.client
    config = browser.lab.config
    path = "/api/v1/dashboard/servers/" + str(server["id"]) + "/ansible"
    headers = {"x-csrf-token": browser.csrf}
    if method == "password":
        credentials = {"password": ssh_target["password"]}
        wrong_credentials = {"password": secrets.token_urlsafe(24)}
    else:
        private, phrase = ssh_target["keys"][method == "encrypted-key"]
        credentials = {"private_key": private, "passphrase": phrase}
        wrong_credentials = {"private_key": ssh_target["keys"][1][0], "passphrase": "invalid"}
    auth_method = "password" if method == "password" else "key"
    response = await client.put(
        path,
        headers=headers,
        json={
            "version": 0,
            "host": ssh_target["address"],
            "port": 22,
            "username": "collector",
            "auth_method": auth_method,
            **credentials,
            "use_sudo": False,
        },
    )
    assert response.status_code == 200, response.text
    settings = Settings(
        app_env="test",
        database=browser.lab.database("ansible_worker"),
        keyring_file=config.root / ".runtime/services" / config.project / "ssh-keys.json",
        work_directory=tmp_path / "private-work",
    )
    database = Database(settings.database)
    database.open()
    service = Service(database, settings)
    repository = JobRepository(database, service.registry())
    with browser.lab.owner() as session:
        session.execute("UPDATE automation.workflow_settings SET enabled=true,auto_updates=false")

    async def execute(action: str, success: bool = True) -> str:
        response = await client.post(path + "/" + action, headers=headers)
        assert response.status_code == 202, response.text
        assert await repository.claim(uuid4(), 60) is None
        with db.connect(config, "workflow_control") as session:
            session.execute(
                "SELECT automation.workflow_dispatch('inventory','fixture-managed'"
                ",'cve-control-inventory')"
            )
        job = await repository.claim(uuid4(), 60)
        assert job is not None
        context = ExecutionContext(
            repository, job, repository.registry.get(job.job_type, 1), asyncio.Event()
        )
        result = await service.handle(context, Request.model_validate(job.payload))
        with browser.lab.owner() as inspect:
            outcome = inspect.execute(
                "SELECT state,error_code FROM inventory.ansible_runs WHERE job_id=%s", (job.id,)
            ).fetchone()
        assert result.success == success, outcome
        return str(response.json()["run_id"])

    try:
        await execute("probe")
        state = (await client.get(path)).json()
        public = state["runs"][0]["host_key"].split()[-1]
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(public)).digest()
        ).decode().rstrip("=")
        response = await client.post(
            path + "/confirm-key", json={"fingerprint": fingerprint}, headers=headers
        )
        assert response.status_code == 200, response.text
        with browser.lab.owner() as inspect:
            event = inspect.execute(
                "SELECT metadata FROM security.audit_log WHERE object_id=%s "
                "AND action='ansible.host_key_confirmed'",
                (str(server["id"]),),
            ).fetchall()
            assert len(event) == 1
            assert event[0]["metadata"] == {"profile_version": 1, "fingerprint": fingerprint}
        wrong = await client.put(
            path,
            headers=headers,
            json={
                "version": 1,
                "host": ssh_target["address"],
                "username": "collector",
                "port": 22,
                "auth_method": auth_method,
                **wrong_credentials,
                "use_sudo": False,
            },
        )
        assert wrong.status_code == 200
        failed = await execute("test", success=False)
        with browser.lab.owner() as session:
            assert (
                session.execute(
                    "SELECT j.status FROM inventory.ansible_runs r "
                    "JOIN automation.jobs j ON j.id=r.job_id WHERE r.id=%s",
                    (failed,),
                ).fetchone()["status"]
                == "failed"
            )
        fixed = await client.put(
            path,
            headers=headers,
            json={
                "version": 2,
                "host": ssh_target["address"],
                "username": "collector",
                "port": 22,
                "auth_method": auth_method,
                **credentials,
                "use_sudo": False,
            },
        )
        assert fixed.status_code == 200
        await execute("test")
        run = await execute("collect")
        with browser.lab.owner() as session:
            row = session.execute(
                "SELECT submission_id,execution_id,state FROM inventory.ansible_runs WHERE id=%s",
                (run,),
            ).fetchone()
            assert row["state"] == "succeeded" and row["execution_id"] == "fixture-managed"
            assert row["submission_id"]
        with db.connect(config, "workflow_control") as session:
            session.execute(
                "SELECT automation.workflow_dispatch('inventory','fixture-inventor"
                "y','cve-control-inventory')"
            )
        with browser.lab.owner() as session:
            session.execute("UPDATE automation.workflow_settings SET enabled=false")
        await drain(browser)
        with browser.lab.owner() as session:
            assert session.execute(
                "SELECT 1 FROM inventory.snapshots WHERE submission_id=%s", (row["submission_id"],)
            ).fetchone()
        assert list(settings.work_directory.iterdir()) == []
        # Delete during a real collection: no late publication may recreate the server.
        from cve_common.jobs.errors import LeaseLost

        with browser.lab.owner() as session:
            session.execute("UPDATE automation.workflow_settings SET enabled=true")
            version = session.execute(
                "SELECT version FROM inventory.servers WHERE id=%s", (server["id"],)
            ).fetchone()["version"]
        pending_run = await client.post(path + "/collect", headers=headers)
        assert pending_run.status_code == 202
        with db.connect(config, "workflow_control") as session:
            session.execute(
                "SELECT automation.workflow_dispatch('inventory','fixture-cancel',"
                "'cve-control-inventory')"
            )
        job = await repository.claim(uuid4(), 60)
        assert job is not None
        context = ExecutionContext(
            repository, job, repository.registry.get(job.job_type, 1), asyncio.Event()
        )
        running = asyncio.create_task(service.handle(context, Request.model_validate(job.payload)))
        for _ in range(100):
            if list(settings.work_directory.glob("ansible-*")):
                break
            await asyncio.sleep(0.05)
        assert not list(settings.work_directory.glob("*/plan.json"))
        deleted = await client.delete(
            path.removesuffix("/ansible"), headers={**headers, "if-match": f'"{version}"'}
        )
        assert deleted.status_code == 204, deleted.text
        with pytest.raises(LeaseLost):
            await asyncio.wait_for(running, 10)
        assert list(settings.work_directory.iterdir()) == []
        with browser.lab.owner() as session:
            assert not session.execute(
                "SELECT 1 FROM inventory.servers WHERE id=%s", (server["id"],)
            ).fetchone()

    finally:
        with browser.lab.owner() as session:
            session.execute("UPDATE automation.workflow_settings SET enabled=false")
        await database.close()
