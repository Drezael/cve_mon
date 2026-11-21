"""Real n8n workflows drive an isolated inventory/CVE pipeline and recover after outage."""

import asyncio
import json
import time
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure import mail
from scripts.infrastructure.manage import Config, compose
from scripts.notifications import manage as notifications
from scripts.workflows import manage as workflows
from tests.authentication.integration.conftest import Lab as UploadLab
from tests.cve_importer.conftest import Lab as SourceLab
from tests.cve_importer.test_git_source import configure, write
from tests.cve_importer.test_git_source import upstream as upstream
from tests.cve_importer.test_pipeline import Harness as Importer
from tests.inventory_upload.integration.conftest import Browser, isolated_upload_lab
from tests.inventory_upload.integration.conftest import browser as browser

pytestmark = pytest.mark.orchestration


@pytest.fixture(scope="module")
def upload_lab() -> Iterator[UploadLab]:
    yield from isolated_upload_lab()


@pytest.fixture(scope="module")
def platform(upload_lab: UploadLab) -> Iterator[Config]:
    from cve_importer.contracts import Configuration

    config = upload_lab.config
    paused = config.root / ".runtime" / (config.project + "-source-fixture.yml")
    paused.write_text(
        "services:\n  cve-processing:\n    environment:\n      CVE_IMPORTER_PAUSED: 'true'\n"
    )
    config = replace(config, compose_overrides=(*config.compose_overrides, paused))
    with db.connect(config) as s:
        s.execute(
            "UPDATE automation.workflow_settings SET "
            "enabled=true,auto_updates=false,source_config=%s::jsonb",
            (Configuration().model_dump_json(),),
        )
    notifications.build(config)
    mail.prepare(config)
    mail.start(config)
    notifications.start(config)
    workflows.prepare(config)
    # Dispatcher targets are read once at process startup, before namespace guards release it.
    from scripts.application.manage import start as start_group

    start_group(config, "cve-processing", force=True)
    notifications.guard(config)
    compose(config, ["up", "-d", "--wait", "--wait-timeout", "90", "cve-processing", "cve-n8n"])
    try:
        yield config
    finally:
        (config.root / ".runtime/workflow-n8n-last.log").write_text(
            compose(config, ["logs", "--no-color", "cve-n8n"]).stdout
        )
        with db.connect(config, database="n8n") as s:
            error_rows = s.execute(
                "SELECT d.data FROM execution_data d JOIN execution_entity e ON "
                'e.id=d."executionId" WHERE e."workflowId"=\'cve-control-queue\' AND'
                " e.status='error' ORDER BY e.id DESC LIMIT 2"
            ).fetchall()
            diagnostic = config.root / ".runtime/n8n-queue-fixture-errors.json"
            diagnostic.write_text(json.dumps(error_rows))
            diagnostic.chmod(0o600)
            print(
                "control-workflow-state",
                s.execute(
                    'SELECT id,active,"isArchived","activeVersionId" FROM workflow_entity '
                    "WHERE id LIKE 'cve-control-%'"
                ).fetchall(),
            )
            print(
                "control-executions",
                s.execute(
                    'SELECT id,"workflowId",status FROM execution_entity ORDER BY id DESC LIMIT 15'
                ).fetchall(),
            )

        with db.connect(config) as s:
            s.execute("UPDATE automation.workflow_settings SET enabled=false")
        compose(config, ["stop", "cve-processing", "cve-n8n"])
        paused.unlink(missing_ok=True)


def eventually(
    config: Config, query: str, params: tuple[Any, ...] = (), seconds: int = 90
) -> dict[str, Any]:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        with db.connect(config) as s:
            row = s.execute(query, params).fetchone()
        if row and row.get("ready"):
            return row
        time.sleep(0.5)
    raise AssertionError("Timed out waiting for the actual n8n-controlled operation")


def test_master_and_subworkflows_are_published_and_private(platform: Config) -> None:
    with db.connect(platform, database="n8n") as s:
        rows = s.execute(
            "SELECT id,active FROM public.workflow_entity WHERE id LIKE 'cve-control-%'"
        ).fetchall()
        assert len(rows) == 10 and all(r["active"] for r in rows)
    eventually(
        platform,
        "SELECT EXISTS(SELECT 1 FROM automation.workflow_requests WHERE stage='status' AND "
        "execution_id IS NOT NULL) AS ready",
    )


async def test_real_workflow_controls_native_cve_to_findings(
    platform: Config, browser: Browser, tmp_path: Path, upstream: tuple[Path, Callable[[], str]]
) -> None:
    from tests.inventory_upload.integration.test_discovery import document, upload, uploader

    root, commit = upstream
    identity = "CVE-2095-96001"
    path = write(root, identity)
    raw = json.loads(path.read_text())
    raw["containers"]["cna"]["affected"] = [
        {
            "vendor": "Apache",
            "product": "apache2",
            "defaultStatus": "unknown",
            "versions": [
                {"version": "0", "lessThan": "99", "versionType": "debian", "status": "affected"}
            ],
        }
    ]
    path.write_text(json.dumps(raw))
    commit()
    await uploader(browser)
    accepted = await upload(browser, document())
    assert accepted.status_code == 202
    receipt = accepted.json()
    # No host-side inventory/matcher/finding drain: the deployed workers must receive n8n approval.
    await asyncio.to_thread(
        eventually,
        platform,
        "SELECT status='completed' AS ready FROM inventory.processing_status WHERE "
        "submission_id=%s",
        (receipt["submission_id"],),
    )
    importer = Importer(SourceLab(platform), tmp_path / "source")
    configure(importer)
    try:
        run = importer.schedule("cve_list")
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT j.status='queued' AS ready FROM cve.import_runs r JOIN automation.jobs "
            "j ON j.id=r.job_id WHERE r.id=%s",
            (run,),
        )
        await importer.execute()
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT EXISTS(SELECT 1 FROM findings.current_findings WHERE cve_id=%s AND "
            "status='open') AS ready",
            (identity,),
        )
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT bool_and(w.execution_id IS NOT NULL) AS ready "
            "FROM automation.workflow_requests w JOIN cve.import_runs r "
            "ON r.correlation_id=w.correlation_id WHERE r.id=%s",
            (run,),
        )
        with db.connect(platform) as s:
            requests = s.execute(
                "SELECT w.stage,w.execution_id,w.workflow_id FROM "
                "automation.workflow_requests w JOIN cve.import_runs r ON "
                "r.correlation_id=w.correlation_id WHERE r.id=%s",
                (run,),
            ).fetchall()
            assert {"import", "index", "matching", "findings"} <= {r["stage"] for r in requests}
            assert all(
                r["execution_id"]
                and r["workflow_id"] in {"cve-control-queue", "cve-control-" + r["stage"]}
                for r in requests
            )
    finally:
        await importer.transport.close()
        await importer.database.close()


def test_n8n_outage_keeps_new_phase_pending_and_recovers(platform: Config) -> None:
    compose(platform, ["stop", "cve-n8n"])
    correlation = uuid4()
    try:
        with db.connect(platform, "api_security") as s:
            job = s.execute(
                "SELECT id FROM "
                "automation.enqueue_job('matching.reconcile',1,'{}'::jsonb,%s,%s,0,NULL,NULL,3,'outage-"
                "test',false)",
                (str(uuid4()), correlation),
            ).fetchone()
        assert job
        time.sleep(2)
        with db.connect(platform) as s:
            state = s.execute(
                "SELECT status FROM automation.jobs WHERE id=%s", (job["id"],)
            ).fetchone()
            assert state and state["status"] == "pending"
    finally:
        compose(platform, ["up", "-d", "--wait", "--wait-timeout", "90", "cve-n8n"])
        notifications.guard(platform)
    eventually(
        platform,
        "SELECT execution_id IS NOT NULL AS ready FROM automation.workflow_requests WHERE "
        "job_id=%s",
        (job["id"],),
    )


async def test_dashboard_schedule_requires_admin_and_csrf(
    platform: Config, browser: Browser
) -> None:
    from tests.authorization.integration.conftest import actor, call

    admin = await actor(browser)
    response = await call(browser, admin, "GET", "orchestration")
    assert response.status_code == 200
    assert response.json()["enabled"] is True
    assert len(response.json()["stages"]) == 8
    response = await call(
        browser,
        admin,
        "PUT",
        "orchestration/settings",
        {
            "auto_updates": False,
            "update_interval": 900,
        },
    )
    assert response.status_code == 200
    assert response.json()["update_interval"] == 900
    response = await browser.client.put(
        "/api/v1/dashboard/orchestration/settings",
        json={"auto_updates": True, "update_interval": 900},
        headers={"x-csrf-token": "invalid"},
    )
    assert response.status_code == 403
    viewer = await actor(browser, roles=("viewer",))
    response = await call(browser, viewer, "GET", "orchestration")
    assert response.status_code == 403


async def test_multiuser_full_catalog_delta_and_server_deletion(
    platform: Config,
    browser: Browser,
    tmp_path: Path,
    upstream: tuple[Path, Callable[[], str]],
) -> None:
    from tests.inventory_upload.integration.test_discovery import document, upload, uploader

    root, commit = upstream
    identities = ["CVE-2095-99001", "CVE-2095-99002", "CVE-2095-99003"]
    paths = {}

    def write_cve(identity: str) -> None:
        path = write(root, identity)
        raw = json.loads(path.read_text())
        raw["containers"]["cna"]["affected"] = [
            {
                "vendor": "Apache",
                "product": "apache2",
                "defaultStatus": "unknown",
                "versions": [
                    {
                        "version": "0",
                        "lessThan": "99",
                        "versionType": "debian",
                        "status": "affected",
                    }
                ],
            }
        ]
        path.write_text(json.dumps(raw))
        paths[identity] = path

    for identity in identities[:2]:
        write_cve(identity)
    commit()
    importer = Importer(SourceLab(platform), tmp_path / "all-users-source")
    configure(importer)

    async def import_run(mode: str = "initial") -> Any:
        run = importer.schedule("cve_list", mode)
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT j.status='queued' AS ready FROM cve.import_runs r "
            "JOIN automation.jobs j ON j.id=r.job_id WHERE r.id=%s",
            (run,),
        )
        await importer.execute()
        return run

    async def findings_for(ids: list[str], expected: int) -> None:
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT count(*)=%s AS ready FROM findings.current_findings "
            "WHERE server_id=ANY(%s::uuid[]) AND cve_id=ANY(%s) AND status='open'",
            (expected, ids, identities),
        )

    async def count_for(actor: Any) -> int:
        response = await browser.client.get(
            "/api/v1/findings/active-count",
            headers={"cookie": "__Host-cve-session=" + actor.cookie},
        )
        assert response.status_code == 200
        return int(response.json()["count"])

    try:
        await import_run()
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT count(*)=2 AS ready FROM cve.enrichment_identities e "
            "JOIN matching.indexed_revisions m ON m.enrichment_revision_id=e.current_revision_id "
            "WHERE e.identity=ANY(%s)",
            (identities[:2],),
        )
        actors, receipts = [], []
        for _ in range(3):
            actors.append(await uploader(browser))
            result = await upload(browser, document())
            assert result.status_code == 202
            receipts.append(result.json())
        servers = [r["server_id"] for r in receipts]
        await findings_for(servers, 6)
        for actor in actors:
            assert await count_for(actor) == 2, "Counts must not include other users findings"
        with db.connect(platform) as s:
            baseline = s.execute(
                "SELECT server_id,identity,count(*) AS n FROM matching.result_revisions "
                "WHERE server_id=ANY(%s::uuid[]) AND identity=ANY(%s) GROUP BY server_id,identity",
                (servers, identities),
            ).fetchall()
        endpoint = "/api/v1/dashboard/servers/" + servers[0]
        details = await browser.client.get(
            "/api/v1/dashboard/security/servers/" + servers[0],
            headers={"cookie": "__Host-cve-session=" + actors[0].cookie},
        )
        assert details.status_code == 200 and details.json()["can_delete"]
        deleted = await browser.client.delete(
            endpoint,
            headers={
                "cookie": "__Host-cve-session=" + actors[0].cookie,
                "x-csrf-token": actors[0].csrf,
                "if-match": '"' + str(details.json()["version"]) + '"',
            },
        )
        assert deleted.status_code == 204
        assert await count_for(actors[0]) == 0
        raw = json.loads(paths[identities[0]].read_text())
        raw["containers"]["cna"]["descriptions"][0]["value"] = "Changed CVE; requires reassessment"
        paths[identities[0]].write_text(json.dumps(raw))
        write_cve(identities[2])
        commit()
        delta = await import_run("incremental")
        await findings_for(servers[1:], 6)
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT count(*)=2 AS ready FROM matching.result_revisions "
            "WHERE server_id=ANY(%s::uuid[]) AND identity=%s AND "
            "enrichment_revision_id IN (SELECT current_revision_id FROM cve.enrichment_identities "
            "WHERE identity=%s)",
            (servers[1:], identities[0], identities[0]),
        )
        with db.connect(platform) as s:
            after = s.execute(
                "SELECT server_id,identity,count(*) AS n FROM matching.result_revisions "
                "WHERE server_id=ANY(%s::uuid[]) AND identity=ANY(%s) GROUP BY server_id,identity",
                (servers, identities),
            ).fetchall()
            original = {(str(r["server_id"]), r["identity"]): r["n"] for r in baseline}
            current = {(str(r["server_id"]), r["identity"]): r["n"] for r in after}
            for server in servers[1:]:
                assert current[(server, identities[1])] == original[(server, identities[1])]
            for server in servers[1:]:
                assert current[(server, identities[0])] == original[(server, identities[0])] + 1
                assert current[(server, identities[2])] == 1
            assert not any(server == servers[0] for server, _ in current)
            assert (servers[0], identities[2]) not in current
            delta_row = s.execute(
                "SELECT read_count FROM cve.import_runs WHERE id=%s", (delta,)
            ).fetchone()
            assert delta_row and delta_row["read_count"] == 2
        for actor in actors[1:]:
            assert await count_for(actor) == 3
        late = await uploader(browser)
        receipt = (await upload(browser, document())).json()
        await findings_for([receipt["server_id"]], 3)
        assert await count_for(late) == 3, "New server must find old and newly added CVEs"
        noop = await import_run("incremental")
        with db.connect(platform) as s:
            noop_row = s.execute(
                "SELECT read_count FROM cve.import_runs WHERE id=%s", (noop,)
            ).fetchone()
            assert noop_row and noop_row["read_count"] == 0
            assert not s.execute(
                "SELECT 1 FROM automation.workflow_requests w JOIN cve.import_runs r "
                "ON r.correlation_id=w.correlation_id WHERE r.id=%s "
                "AND w.stage IN ('index','matching')",
                (noop,),
            ).fetchone()
    finally:
        await importer.transport.close()
        await importer.database.close()


async def test_n8n_schedules_outbound_container_collection(
    platform: Config, browser: Browser
) -> None:
    from tests.inventory_upload.integration.test_collection import credential
    from tests.matching.test_container_inventory import inventory

    cid, headers = await credential(browser)
    prefix = "/api/v1/inventories/collection/"
    response = await browser.technical_client.post(
        prefix + "targets",
        headers=headers,
        json={"alias": "docker-application-host", "interval_seconds": 21600},
    )
    assert response.status_code == 200, response.text
    target = response.json()["result"]
    eventually(
        platform,
        "SELECT EXISTS(SELECT 1 FROM inventory.collection_requests WHERE target_id=%s "
        "AND workflow_id='cve-control-inventory' AND execution_id IS NOT NULL) AS ready",
        (target,),
    )
    claimed = await browser.technical_client.post(prefix + "claim", headers=headers, json={})
    assert claimed.status_code == 200, claimed.text
    job = claimed.json()["result"]
    assert job and job["workflow_id"] == "cve-control-inventory"
    value = inventory()
    # Real technical upload; the existing mTLS ingress and n8n authorize processing.
    response = await browser.technical_client.post(
        "/api/v1/inventories",
        headers=headers | {"content-type": "application/json"},
        content=json.dumps(value).encode(),
    )
    assert response.status_code == 202, response.text
    receipt = response.json()
    completed = await browser.technical_client.post(
        prefix + "finish",
        headers=headers,
        json={
            "request_id": job["request_id"],
            "lease_token": job["lease_token"],
            "submission_id": receipt["submission_id"],
        },
    )
    assert completed.status_code == 200, completed.text
    eventually(
        platform,
        "SELECT EXISTS(SELECT 1 FROM inventory.processing_status WHERE submission_id=%s "
        "AND status='completed') AS ready",
        (receipt["submission_id"],),
    )
    with db.connect(platform) as s:
        state = s.execute(
            "SELECT r.state,t.server_id FROM inventory.collection_requests r "
            "JOIN inventory.collection_targets t ON t.id=r.target_id WHERE r.id=%s",
            (job["request_id"],),
        ).fetchone()
        assert (
            state
            and state["state"] == "succeeded"
            and str(state["server_id"]) == receipt["server_id"]
        )
        bills = s.execute("SELECT count(*) AS n FROM inventory.software_bills").fetchone()
        assert bills and bills["n"] > 0


async def test_n8n_restarts_only_the_selected_process_in_its_existing_container(
    platform: Config, browser: Browser
) -> None:
    from scripts.application.manage import identity
    from scripts.automation_executor.agent import process_restart
    from scripts.infrastructure.manage import docker_command, run
    from tests.authorization.integration.conftest import actor

    person = await actor(browser)
    for target, group, role in [
        ("importer", "cve-processing", "cve-importer"),
        ("api", "cve-api", "cve-api"),
        ("notification", "cve-processing", "cve-notification"),
    ]:
        before = identity(platform, group)
        state = json.loads(
            run(
                [*docker_command(), "exec", before["Id"], "cat", "/tmp/cve-application-state.json"]
            ).stdout
        )
        response = await browser.client.post(
            "/api/v1/status/services/" + target + "/restart",
            headers={
                "cookie": "__Host-cve-session=" + person.cookie,
                "x-csrf-token": person.csrf,
                "Idempotency-Key": str(uuid4()),
            },
            json={"reason": "Native n8n process restart verification"},
        )
        assert response.status_code == 202, response.text
        request = response.json()["id"]
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT state='authorized' AND authorized_at<clock_timestamp()-interval '2 seconds' "
            "AS ready FROM status.service_restarts WHERE id=%s",
            (request,),
        )
        await asyncio.to_thread(process_restart, platform)
        with db.connect(platform) as s:
            receipt = s.execute(
                "SELECT state,execution_id,old_pid,new_pid,error_code "
                "FROM status.service_restarts WHERE id=%s",
                (request,),
            ).fetchone()
        assert receipt and receipt["state"] == "succeeded", receipt
        assert receipt["execution_id"].isdigit()
        assert receipt["old_pid"] != receipt["new_pid"]
        after = identity(platform, group)
        assert after["Id"] == before["Id"]
        assert after["State"]["Pid"] == before["State"]["Pid"]
        assert after["State"]["StartedAt"] == before["State"]["StartedAt"]
        current = json.loads(
            run(
                [*docker_command(), "exec", after["Id"], "cat", "/tmp/cve-application-state.json"]
            ).stdout
        )
        assert current["children"][role] != state["children"][role]
        for peer, pid in state["children"].items():
            if peer != role:
                assert current["children"][peer] == pid
        # Repeating delivery of the same restart UUID reads its local receipt.
        result = json.loads(
            run(
                [
                    *docker_command(),
                    "exec",
                    after["Id"],
                    "python",
                    "-m",
                    "cve_common.application",
                    "restart",
                    role,
                    request,
                ]
            ).stdout
        )
        assert result["new_pid"] == current["children"][role]


async def test_smtp_settings_apply_through_real_n8n_without_restarting_containers(
    platform: Config, browser: Browser, tmp_path: Path
) -> None:
    import secrets

    from scripts.infrastructure.manage import docker_command, run
    from scripts.smtp.manage import process
    from tests.authorization.integration.conftest import actor

    person = await actor(browser)
    secret = secrets.token_urlsafe(32)
    ids = run(
        [
            *docker_command(),
            "ps",
            "-q",
            "--filter",
            "label=com.docker.compose.project=" + platform.project,
        ]
    ).stdout.split()
    before = json.loads(run([*docker_command(), "inspect", *ids]).stdout)
    endpoint = "/api/v1/dashboard/administration/smtp"
    response = await browser.client.put(
        endpoint,
        headers={
            "cookie": "__Host-cve-session=" + person.cookie,
            "x-csrf-token": person.csrf,
            "Idempotency-Key": str(uuid4()),
        },
        json={
            "version": 0,
            "enabled": False,
            "host": "smtp.example.test",
            "port": 587,
            "sender": "security@example.test",
            "recipients": ["user@example.test"],
            "username": "fixture-smtp",
            "password": secret,
        },
    )
    assert response.status_code == 202, response.text
    identity = response.json()["id"]
    assert secret not in response.text
    await asyncio.to_thread(
        eventually,
        platform,
        "SELECT c.state='authorized' AND q.finished_at<clock_timestamp()-interval '2 seconds' "
        "AS ready FROM automation.smtp_configs c JOIN automation.n8n_queue q "
        "ON q.id=c.queue_id "
        "WHERE c.id=%s",
        (identity,),
    )
    await asyncio.to_thread(process, platform)
    with db.connect(platform) as s:
        row = s.execute(
            "SELECT state,error_code,execution_id FROM automation.smtp_configs WHERE id=%s",
            (identity,),
        ).fetchone()
        assert row and row["state"] == "applied", row
        assert row["execution_id"].isdigit()
    await asyncio.to_thread(
        eventually,
        platform,
        "SELECT count(*)=2 AND bool_and(state='completed') AS ready "
        "FROM automation.n8n_queue WHERE correlation_id=%s",
        (identity,),
    )
    # Enable and disable the native route as separate n8n commands; never submit mail.
    for version, enabled in [(1, True), (2, False)]:
        response = await browser.client.put(
            endpoint,
            headers={
                "cookie": "__Host-cve-session=" + person.cookie,
                "x-csrf-token": person.csrf,
                "Idempotency-Key": str(uuid4()),
            },
            json={
                "version": version,
                "enabled": enabled,
                "host": "smtp.example.test",
                "port": 587,
                "sender": "security@example.test",
                "recipients": ["user@example.test"],
                "username": "fixture-smtp",
                "password": None,
            },
        )
        assert response.status_code == 202, response.text
        next_id = response.json()["id"]
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT c.state='authorized' AND q.finished_at<clock_timestamp()-interval '2 seconds' "
            "AS ready FROM automation.smtp_configs c JOIN automation.n8n_queue q "
            "ON q.id=c.queue_id "
            "WHERE c.id=%s",
            (next_id,),
        )
        await asyncio.to_thread(process, platform)
        with db.connect(platform) as s:
            applied = s.execute(
                "SELECT state,error_code FROM automation.smtp_configs WHERE id=%s", (next_id,)
            ).fetchone()
            assert applied and applied["state"] == "applied", applied
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT count(*)=2 AND bool_and(state='completed') AS ready "
            "FROM automation.n8n_queue WHERE correlation_id=%s",
            (next_id,),
        )
        if enabled:
            from scripts.application.manage import identity as application_identity

            group = application_identity(platform, "cve-processing")
            code = (
                "import ssl,smtplib;ctx=ssl.create_default_context("
                "cafile='/run/cve-notification/smtp-ca.crt');"
                "ctx.load_cert_chain('/run/cve-notification/smtp-client.crt','/run/cve-notification/smtp-client.key');"
                "c=smtplib.SMTP('cve-mail-submit',2525,timeout=5);c._host='cve-mail-relay';"
                "assert c.ehlo()[0]==250;c.starttls(context=ctx);assert c.ehlo()[0]==250;c.quit()"
            )
            run([*docker_command(), "exec", group["Id"], "python", "-c", code])
    # Two independent personal transports, including identical visible From addresses.
    reader = await actor(browser, ("viewer",))
    profiles = []
    for user, host, username in [
        (person, "smtp.first.example.test", "first-user"),
        (reader, "smtp.second.example.test", "second-user"),
    ]:
        password = secrets.token_urlsafe(32)
        response = await browser.client.put(
            "/api/v1/dashboard/notifications/mail",
            headers={
                "cookie": "__Host-cve-session=" + user.cookie,
                "x-csrf-token": user.csrf,
                "Idempotency-Key": str(uuid4()),
            },
            json={
                "version": 0,
                "mode": "custom",
                "enabled": True,
                "host": host,
                "port": 587,
                "sender": "shared@example.test",
                "recipients": ["first@example.test", "second@example.test"],
                "username": username,
                "password": password,
            },
        )
        assert response.status_code == 202, response.text
        identity = response.json()["id"]
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT c.state='authorized' AND q.finished_at<clock_timestamp()-interval "
            "'2 seconds' AS ready FROM automation.smtp_configs c JOIN automation.n8n_queue q "
            "ON q.id=c.queue_id WHERE c.id=%s",
            (identity,),
        )
        await asyncio.to_thread(process, platform)
        with db.connect(platform) as connection:
            applied = connection.execute(
                "SELECT state,error_code FROM automation.smtp_configs WHERE id=%s", (identity,)
            ).fetchone()
            assert applied and applied["state"] == "applied", applied
        profiles.append((user, host, username, password))
    from scripts.infrastructure import envoy, mail
    from scripts.notifications.manage import directory as notification_directory

    relay = mail.container(platform)["Id"]
    public_profiles = json.loads(
        (mail.directory(platform) / "state/smtp-profiles.json").read_text()
    )
    assert len(public_profiles) == 2
    assert len({p["listen_port"] for p in public_profiles}) == 2
    assert len({p["envelope_sender"] for p in public_profiles}) == 2
    routes = json.loads((notification_directory(platform) / "smtp-delivery.json").read_text())
    for user, host, username, password in profiles:
        envelope = routes[str(user.id)]["envelope_sender"]
        upstream = next(p for p in public_profiles if p["envelope_sender"] == envelope)
        assert upstream["host"] == host
        saved_auth = run(
            [
                *docker_command(),
                "exec",
                "--user",
                "0",
                relay,
                "postmap",
                "-q",
                envelope,
                "texthash:/run/postfix/sasl-passwd",
            ]
        ).stdout.strip()
        assert saved_auth == username + ":" + password
        saved_relay = run(
            [
                *docker_command(),
                "exec",
                "--user",
                "0",
                relay,
                "postmap",
                "-q",
                envelope,
                "texthash:/run/postfix/sender-relays",
            ]
        ).stdout.strip()
        assert saved_relay == "[cve-egress-proxy]:" + str(upstream["listen_port"])
        assert password not in json.dumps(public_profiles) and password not in json.dumps(routes)
    policy = json.loads((envoy.directory(platform) / "policy.json").read_text())
    assert not policy["smtp"]["enabled"] and len(policy["smtp"]["routes"]) == 2
    # Both custom routes remain usable even though the central SMTP server is disabled.
    # RSET before DATA proves recipient admission without placing any message in the queue.
    from scripts.application.manage import identity as application_identity

    group = application_identity(platform, "cve-processing")
    code = (
        "import ssl,smtplib,json;ctx=ssl.create_default_context("
        "cafile='/run/cve-notification/smtp-ca.crt');"
        "ctx.load_cert_chain('/run/cve-notification/smtp-client.crt','/run/cve-notification/smtp-client.key');"
        "c=smtplib.SMTP('cve-mail-submit',2525,timeout=5);c._host='cve-mail-relay';"
        "c.ehlo();c.starttls(context=ctx);c.ehlo();"
        "routes=json.load(open('/run/cve-notification/smtp-delivery.json'));"
        "exec("
        + repr(
            "for p in routes.values():\n"
            " assert c.mail(p['envelope_sender'])[0]==250\n"
            " assert c.rcpt('first@example.test')[0]==250\n"
            " assert c.rcpt('second@example.test')[0]==250\n c.rset()"
        )
        + ");c.quit()"
    )
    run([*docker_command(), "exec", group["Id"], "python", "-c", code])

    from scripts.infrastructure import mail

    await asyncio.to_thread(
        verify_personal_provider_delivery, platform, profiles, tmp_path / "providers"
    )
    for _ in range(30):
        if not mail.queue(platform):
            break
        await asyncio.sleep(0.2)
    assert mail.queue(platform) == []
    current = json.loads(run([*docker_command(), "inspect", *ids]).stdout)
    assert all(
        v["Id"] == old["Id"]
        and v["State"]["Pid"] == old["State"]["Pid"]
        and v["State"]["StartedAt"] == old["State"]["StartedAt"]
        for v, old in zip(current, before, strict=True)
    )


def verify_personal_provider_delivery(config: Config, profiles: list[Any], directory: Path) -> None:
    """Real native Postfix/TLS/AUTH against two private sinks; no external mail delivery."""
    import os
    import shutil
    import subprocess

    from cve_common.smtp_settings import SMTPConfig

    from scripts.infrastructure import envoy
    from scripts.infrastructure.manage import docker_command, run
    from scripts.smtp.manage import apply, reload_postfix
    from tests.infrastructure.envoy.conftest import PYTHON_IMAGE

    base = mail.directory(config)
    sinks: list[str] = []
    addresses = []

    def control(sink: str, value: dict[str, Any] | None = None) -> dict[str, Any]:
        program = (
            "import json,urllib.request;u='http://127.0.0.1:8080/control';"
            + (
                "urllib.request.urlopen(urllib.request.Request(u,data="
                + repr(json.dumps(value).encode())
                + ",method='POST')).close();"
                if value
                else ""
            )
            + "print(urllib.request.urlopen(u).read().decode())"
        )
        return dict(
            json.loads(run([*docker_command(), "exec", sink, "python", "-c", program]).stdout)
        )

    try:
        for index, (_user, host, username, password) in enumerate(profiles):
            files = directory / str(index)
            files.mkdir(parents=True, mode=0o755)
            certificate = "personal-upstream-" + str(index)
            mail.certificate(base / "pki", certificate, "upstream-ca", host)
            shutil.copyfile(base / "pki" / (certificate + ".crt"), files / "upstream.crt")
            shutil.copyfile(base / "pki/private" / (certificate + ".key"), files / "upstream.key")
            for name, content in [("smtp_username", username), ("smtp_password", password)]:
                path = files / name
                path.write_text(content + "\n")
                path.chmod(0o600)
            shutil.copyfile(
                config.root / "tests/infrastructure/mail/fixtures/smarthost.py",
                files / "smarthost.py",
            )
            shutil.copyfile(
                config.root / "tests/infrastructure/envoy/fixtures/servers.py", files / "base.py"
            )
            sink = config.project + "-personal-sink-" + str(index)
            run(
                [
                    *docker_command(),
                    "run",
                    "-d",
                    "--name",
                    sink,
                    "--network",
                    config.project + "_cve_egress_external",
                    "--user",
                    f"{os.getuid()}:{os.getgid()}",
                    "--cap-drop",
                    "ALL",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,size=8m",
                    "-v",
                    str(files) + ":/fixture:ro",
                    PYTHON_IMAGE,
                    "python",
                    "/fixture/smarthost.py",
                ]
            )
            sinks.append(sink)
            info = envoy.inspect_container(sink)
            address = info["NetworkSettings"]["Networks"][config.project + "_cve_egress_external"][
                "IPAddress"
            ]
            addresses.append(address)
            envoy.namespace_command(
                int(info["State"]["Pid"]),
                ["ip", "address", "add", f"93.184.216.{34 + index}/32", "dev", "lo"],
            )
            for _ in range(30):
                ready = subprocess.run(
                    [*docker_command(), "exec", sink, "test", "-f", "/tmp/fixture-ready"],
                    check=False,
                    capture_output=True,
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("private SMTP sink did not become ready")
        records = {
            host: ["A", f"93.184.216.{34 + index}"]
            for index, (_user, host, _username, _password) in enumerate(profiles)
        }
        control(sinks[0], {"records": records})
        _, pid = envoy.netns(config)
        for index, address in enumerate(addresses):
            envoy.namespace_command(
                pid, ["ip", "route", "add", f"93.184.216.{34 + index}/32", "via", address]
            )
        proxy = envoy.directory(config) / "policy.json"
        policy = json.loads(proxy.read_text())
        policy["dns"] = {
            "address": addresses[0],
            "port": 53,
            "refresh_seconds": 1,
            "timeout_seconds": 1,
        }
        proxy.write_text(json.dumps(policy))
        public = json.loads((base / "state/smtp-profiles.json").read_text())
        credentials = json.loads((base / "secrets/smtp-profiles.json").read_text())
        projected = [{**p, "credentials": credentials[p["envelope_sender"]]} for p in public]
        apply(
            config,
            SMTPConfig(),
            {},
            profiles=projected,
            recipients=["first@example.test", "second@example.test"],
        )
        shutil.copyfile(base / "pki/upstream-ca.crt", base / "state/upstream-ca.crt")
        reload_postfix(config)
        from scripts.application.manage import identity as application_identity

        processing = application_identity(config, "cve-processing")["Id"]
        for profile in projected:
            program = (
                "from pathlib import Path;from email.message import EmailMessage;"
                "from cve_notification.smtp import Adapter;b=Path('/run/cve-notification');"
                "a=Adapter(ca=b/'smtp-ca.crt',certificate=b/'smtp-client.crt',key=b/'smtp-client.key');"
                "m=EmailMessage();m['From']='shared@example.test';"
                "m['To']='first@example.test, second@example.test';"
                "m['Subject']='Private SMTP fixture';"
                "m.set_content('Private two-provider integration fixture');"
                "r=a.submit(m,envelope_sender="
                + repr(profile["envelope_sender"])
                + ",recipients=['first@example.test','second@example.test']);"
                "assert r.status=='relay_accepted',r.status"
            )
            run([*docker_command(), "exec", processing, "python", "-c", program])
        for sink, (_user, host, _username, _password) in zip(sinks, profiles, strict=True):
            for _ in range(80):
                result = control(sink)
                if result["messages"]:
                    break
                time.sleep(0.25)
            else:
                raise AssertionError("private provider did not accept the message")
            assert len(result["messages"]) == 1
            assert result["messages"][0]["sender"] == "shared@example.test"
            assert result["messages"][0]["recipients"] == [
                "first@example.test",
                "second@example.test",
            ]
            assert result["sni"] and all(name == host for name in result["sni"])
            assert (
                result["counters"]["auth"] == 1
                and result["counters"].get("auth_before_tls", 0) == 0
            )
    finally:
        for sink in sinks:
            subprocess.run([*docker_command(), "rm", "-f", sink], check=False, capture_output=True)
