"""Actual n8n regular-mode database, encrypted credentials and private authenticated callbacks."""

import json
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

import pytest

from scripts.infrastructure import envoy, mail
from scripts.infrastructure.manage import Config, compose, docker_command, run
from scripts.notifications import manage
from tests.authentication.integration.conftest import Lab

pytestmark = pytest.mark.notifications


@pytest.fixture(scope="module")
def runtime(upload_lab: Lab) -> Iterator[Config]:
    config = upload_lab.config
    manage.build(config)
    mail.prepare(config)
    mail.start(config)
    try:
        manage.start(config)
    except Exception:
        log = compose(config, ["logs", "--no-log-prefix", "--tail", "60", "cve-n8n"]).stdout
        (config.root / ".runtime/test-reports/phase-19-n8n-runtime-debug.log").write_text(log)
        raise
    try:
        yield config
    finally:
        compose(config, ["stop", "cve-notification", "cve-n8n"])


def execute(config: Config, service: str, program: str) -> str:
    identity = compose(config, ["ps", "-q", service]).stdout.strip()
    return run(
        [
            *docker_command(),
            "exec",
            identity,
            "python" if service == "cve-notification" else "node",
            "-c" if service == "cve-notification" else "-e",
            program,
        ]
    ).stdout


def test_real_n8n_and_notification_readiness(runtime: Config) -> None:
    services = [
        json.loads(row) for row in compose(runtime, ["ps", "--format", "json"]).stdout.splitlines()
    ]
    assert all(
        r["Health"] == "healthy" for r in services if r["Service"] in {"cve-n8n", "cve-processing"}
    )
    value = envoy.inspect_container(compose(runtime, ["ps", "-q", "cve-n8n"]).stdout.strip())
    env = dict(v.split("=", 1) for v in value["Config"]["Env"])
    assert env["EXECUTIONS_MODE"] == "regular" and env["DB_POSTGRESDB_DATABASE"] == "n8n"
    assert not any("REDIS" in k for k in env)


def test_private_callback_rejects_unauthorized(runtime: Config) -> None:
    code = (
        "import urllib.request,urllib.error,ssl\ntry:\n urllib.request.urlop"
        "en(urllib.request.Request('https://localhost:8000/internal/v1/not"
        "ifications/ticks/health',data=b'{}',method='POST'),context=ssl.cr"
        "eate_default_context(cafile='/run/cve-notification/ca.crt'))\nexce"
        "pt urllib.error.HTTPError as e: print(e.code)\n"
    )
    assert execute(runtime, "cve-notification", code).strip() == "401"


async def test_e2e_finding_n8n_mtls_postfix_envoy_and_no_second_submit(
    runtime: Config,
    browser: object,
    tmp_path: object,
    *,
    finding_factory: Callable[[], Awaitable[dict[str, Any]]] | None = None,
) -> None:
    import asyncio
    import os
    import shutil
    from pathlib import Path

    from tests.cve_enricher.test_native import Env
    from tests.cve_importer.conftest import Lab as SourceLab
    from tests.infrastructure.envoy.conftest import PYTHON_IMAGE
    from tests.inventory_upload.integration.conftest import Browser
    from tests.notifications.test_native import Harness

    assert isinstance(browser, Browser)
    assert isinstance(tmp_path, Path)
    assert runtime.project.startswith("cve-db-test-")
    base = mail.directory(runtime)
    pki = base / "pki"
    files = tmp_path / "sink"
    files.mkdir(mode=0o755)
    mail.certificate(pki, "upstream", "upstream-ca", "mail.allowed.test", False, False)
    for name in ["upstream.crt", "upstream.key"]:
        shutil.copyfile(pki / ("private/" + name if name.endswith(".key") else name), files / name)
    shutil.copyfile(base / "secrets/smtp_username", files / "smtp_username")
    shutil.copyfile(base / "secrets/smtp_password", files / "smtp_password")
    shutil.copyfile(
        runtime.root / "tests/infrastructure/mail/fixtures/smarthost.py", files / "smarthost.py"
    )
    shutil.copyfile(
        runtime.root / "tests/infrastructure/envoy/fixtures/servers.py", files / "base.py"
    )
    sink = runtime.project + "-notification-sink"
    run(
        [
            *docker_command(),
            "run",
            "-d",
            "--name",
            sink,
            "--label",
            "org.cve-monitoring.notification-test=" + runtime.project,
            "--network",
            runtime.project + "_cve_egress_external",
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
    harness = None
    try:
        info = envoy.inspect_container(sink)
        address = info["NetworkSettings"]["Networks"][runtime.project + "_cve_egress_external"][
            "IPAddress"
        ]
        envoy.namespace_command(
            int(info["State"]["Pid"]), ["ip", "address", "add", "93.184.216.34/32", "dev", "lo"]
        )
        policy = json.loads((base / "state/policy.json").read_text())
        policy.update(
            enabled=True,
            smarthost="mail.allowed.test",
            port=587,
            recipients=["initial@example.test"],
        )
        fingerprint = (
            run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(pki / "notification.crt"),
                    "-sha256",
                    "-fingerprint",
                    "-noout",
                ]
            )
            .stdout.strip()
            .split("=", 1)[1]
        )
        policy["clients"] = [
            {
                "name": "notification",
                "fingerprint": fingerprint,
                "senders": ["security@cve.example.test"],
                "enabled": True,
                "purpose": "Isolated Phase 19 end-to-end",
            }
        ]
        mail.validate(policy)
        (base / "state/policy.json").write_text(json.dumps(policy))
        epolicy = envoy.policy()
        epolicy["rules"] = []
        epolicy["dns"] = {
            "address": address,
            "port": 53,
            "refresh_seconds": 1,
            "timeout_seconds": 1,
        }
        envoy.render(runtime, epolicy, {})
        mail.start(runtime)
        _, pid = envoy.netns(runtime)
        envoy.namespace_command(pid, ["ip", "route", "add", "93.184.216.34/32", "via", address])
        manage.guard(runtime)
        with browser.lab.owner() as c:
            present = c.execute("SELECT 1 FROM cve.source_revisions LIMIT 1").fetchone()
        if not present and finding_factory is None:
            source = Env(SourceLab(runtime), tmp_path / "source")
            try:
                await source.importer.run("cve_list")
                await source.drain()
            finally:
                await source.importer.transport.close()
                await source.importer.database.close()
                await source.client.close()
                await source.database.close()
        harness = Harness(browser)
        harness.enable()
        f = await finding_factory() if finding_factory else await harness.findings.create()
        with browser.lab.owner() as c:
            intended = c.execute(
                "SELECT id FROM security.users WHERE email='initial@example.test'"
            ).fetchone()["id"]
        chosen = None
        for _ in range(100):
            found = [
                n
                for n in harness.intents()
                if n["finding_id"] == f["id"]
                and n["recipient_user_id"] == intended
                and n["status"] in {"ready", "leased", "submitting", "relay_accepted"}
            ]
            if found:
                chosen = found[0]
                break
            await asyncio.sleep(0.2)
        assert chosen is not None, "Persistent real worker did not create intent"
        code = (
            "import asyncio\nfrom cve_common.config.validation i"
            "mport load_settings\nfrom cve_common.database.engin"
            "e import Database\nfrom cve_notification.contracts "
            "import Settings\nfrom cve_notification.orchestratio"
            "n import trigger\nfrom uuid import UUID\nasync def r"
            "un():\n cfg=load_settings(Settings);db=Database(cfg"
            ".database);db.open()\n try: await trigger(db,UUID('"
            "IDENTITY'))\n finally: await db.close()\nasyncio.run"
            "(run())\n"
        ).replace("IDENTITY", str(chosen["id"]))
        execute(runtime, "cve-notification", code)
        status = "ready"
        for _ in range(200):
            with browser.lab.owner() as c:
                status = c.execute(
                    "SELECT status FROM automation.notification_intents WHERE id=%s",
                    (chosen["id"],),
                ).fetchone()["status"]
            if status == "relay_accepted":
                break
            await asyncio.sleep(0.2)
        if status != "relay_accepted":
            with browser.lab.owner() as c:
                details = c.execute(
                    (
                        "SELECT r.status,r.reason FROM automation.notificat"
                        "ion_delivery_results r JOIN automation.notificatio"
                        "n_delivery_attempts a ON a.id=r.attempt_id WHERE a"
                        ".notification_id=%s"
                    ),
                    (chosen["id"],),
                ).fetchall()
            for service in ["cve-n8n", "cve-notification", "cve-mail-relay"]:
                log = compose(runtime, ["logs", "--no-log-prefix", "--tail", "50", service]).stdout
                (
                    runtime.root / ".runtime/test-reports" / ("phase-19-e2e-" + service + ".log")
                ).write_text(log)
            assert status == "relay_accepted", str((status, details))
        execute(runtime, "cve-notification", code)
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    (
                        "SELECT count(*) n FROM automation.notification_del"
                        "ivery_attempts WHERE notification_id=%s"
                    ),
                    (chosen["id"],),
                ).fetchone()["n"]
                == 1
            )
            result = c.execute(
                (
                    "SELECT r.* FROM automation.notification_delivery_r"
                    "esults r JOIN automation.notification_delivery_att"
                    "empts a ON a.id=r.attempt_id WHERE a.notification_"
                    "id=%s"
                ),
                (chosen["id"],),
            ).fetchone()
            assert result["queue_id"] and result["status"] == "relay_accepted"
        for _ in range(100):
            data = json.loads(
                run(
                    [
                        *docker_command(),
                        "exec",
                        sink,
                        "python",
                        "-c",
                        (
                            "import urllib.request;print(urllib.request.urlopen"
                            "('http://127.0.0.1:8080/control').read().decode())"
                        ),
                    ]
                ).stdout
            )
            if data.get("messages"):
                break
            await asyncio.sleep(0.2)
        assert data.get("messages"), "No message traversed the actual Envoy/SMTP path"
        # The upstream syslog transport and SMTP completion are asynchronous.
        # Poll boundedly; a provider message alone is not delivery evidence.
        for _ in range(50):
            observation = manage.reconcile_postfix(runtime)
            if observation["observations"] >= 1:
                break
            await asyncio.sleep(0.2)
        assert observation["observations"] >= 1
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT status FROM automation.notification_intents WHERE id=%s",
                    (chosen["id"],),
                ).fetchone()["status"]
                == "upstream_accepted"
            )
        with browser.lab.owner() as c:
            before = c.execute(
                "SELECT version FROM automation.notification_intents WHERE id=%s", (chosen["id"],)
            ).fetchone()["version"]
        manage.reconcile_postfix(runtime)
        with browser.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT version FROM automation.notification_intents WHERE id=%s",
                    (chosen["id"],),
                ).fetchone()["version"]
                == before
            )
    finally:
        if harness:
            await harness.database.close()
            await harness.findings.database.close()
            await harness.findings.matcher.database.close()
        run([*docker_command(), "rm", "-f", sink])


def test_container_boundaries_and_encrypted_credentials(runtime: Config) -> None:
    from scripts.database import manage as database

    for service in ["cve-n8n", "cve-notification"]:
        info = envoy.inspect_container(compose(runtime, ["ps", "-q", service]).stdout.strip())
        assert info["HostConfig"]["ReadonlyRootfs"] and not info["HostConfig"]["Privileged"]
        assert info["HostConfig"]["CapDrop"] == ["ALL"] and not info["HostConfig"]["PortBindings"]
        assert info["Config"]["User"].split(":")[0] != "0"
        assert all("docker.sock" not in m["Source"] for m in info["Mounts"])
    key = manage.directory(runtime) / "service-key.current"
    with database.connect(runtime, "n8n_app", "n8n") as c:
        rows = c.execute("SELECT data FROM public.credentials_entity").fetchall()
    safe = bool(rows) and all(key.read_text().strip() not in str(row["data"]) for row in rows)
    assert safe
    assert not (manage.n8n_directory(runtime) / "config/credentials-import.json").exists()


def test_network_guard_denies_internet_metadata_and_api(runtime: Config) -> None:
    api = envoy.inspect_container(compose(runtime, ["ps", "-q", "cve-api"]).stdout.strip())
    peer = next(
        v["IPAddress"]
        for k, v in api["NetworkSettings"]["Networks"].items()
        if k.endswith("_cve_internal")
    )
    code = """import socket,json
out=[]
for host,port in [('93.184.216.34',443),('169.254.169.254',80),('PEER',8000)]:
 try:
  sock=socket.create_connection((host,port),timeout=.5);sock.close();out.append(True)
 except OSError:out.append(False)
print(json.dumps(out))
""".replace("PEER", peer)
    assert not any(json.loads(execute(runtime, "cve-notification", code)))
    node = (
        "const net=require('net');let s=net.connect({host:'"
        "93.184.216.34',port:443});s.setTimeout(500);s.on('"
        "connect',()=>{s.destroy();console.log('true')});s."
        "on('error',()=>console.log('false'));s.on('timeout"
        "',()=>{s.destroy();console.log('false')})"
    )
    assert execute(runtime, "cve-n8n", node).strip() == "false"


def test_callback_bounds_wrong_run_and_no_actor_impersonation(runtime: Config) -> None:
    code = (
        "import urllib.request,urllib.error,ssl,json\nfrom p"
        "athlib import Path\nkey=Path('/run/cve-notification"
        "/service-key.current').read_text().strip()\ncontext"
        "=ssl.create_default_context(cafile='/run/cve-notif"
        "ication/ca.crt')\nresults=[]\nfor data in [b'{}',b'x"
        "'*2049,json.dumps({'run_id':'00000000-0000-0000-00"
        "00-000000000001','request_id':'00000000-0000-0000-"
        "0000-000000000002','actor_user_id':'00000000-0000-"
        "0000-0000-000000000003'}).encode()]:\n request=urll"
        "ib.request.Request('https://localhost:8000/interna"
        "l/v1/notifications/workflows/claim',data=data,head"
        "ers={'X-CVE-Service':key,'Content-Type':'applicati"
        "on/json'})\n try: results.append(urllib.request.url"
        "open(request,context=context,timeout=3).status)\n e"
        "xcept urllib.error.HTTPError as error: results.app"
        "end(error.code)\nprint(json.dumps(results))\n"
    )
    assert json.loads(execute(runtime, "cve-notification", code)) == [422, 413, 422]


def readiness(runtime: Config) -> int:
    code = (
        "import urllib.request,urllib.error,ssl\ncontext=ssl"
        ".create_default_context(cafile='/run/cve-notificat"
        "ion/ca.crt')\ntry:\n print(urllib.request.urlopen('h"
        "ttps://localhost:8000/health/ready',context=contex"
        "t,timeout=5).status)\nexcept urllib.error.HTTPError"
        " as error: print(error.code)\nexcept urllib.error.U"
        "RLError: print(503)\n"
    )
    return int(execute(runtime, "cve-notification", code).strip())


def wait_ready(runtime: Config) -> None:
    import time

    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if readiness(runtime) == 200:
            return
        time.sleep(0.3)
    assert readiness(runtime) == 200


def test_guard_proof_fails_closed(runtime: Config) -> None:
    proof = manage.directory(runtime) / "guard.ready"
    before = proof.read_bytes()
    proof.unlink()
    try:
        assert readiness(runtime) == 503
    finally:
        manage.write(proof, before)
    wait_ready(runtime)


def test_n8n_outage_recovery_preserves_encryption_key(runtime: Config) -> None:
    import hashlib

    key = manage.n8n_directory(runtime) / "config/encryption.key"
    digest = hashlib.sha256(key.read_bytes()).hexdigest()
    compose(runtime, ["stop", "cve-n8n"])
    try:
        assert readiness(runtime) == 503
    finally:
        compose(runtime, ["up", "-d", "cve-n8n"])
        manage.guard(runtime)
        compose(
            runtime, ["up", "-d", "--wait", "--wait-timeout", "90", "cve-notification", "cve-n8n"]
        )
    wait_ready(runtime)
    assert hashlib.sha256(key.read_bytes()).hexdigest() == digest


def test_postgres_outage_and_recovery(runtime: Config) -> None:
    compose(runtime, ["stop", "cve-postgres"])
    try:
        assert readiness(runtime) == 503
    finally:
        compose(runtime, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-postgres"])
        manage.guard(runtime)
        compose(
            runtime, ["up", "-d", "--wait", "--wait-timeout", "90", "cve-notification", "cve-n8n"]
        )
    wait_ready(runtime)


def test_n8n_webhook_requires_its_own_header_credential(runtime: Config) -> None:
    code = (
        "import urllib.request,urllib.error,ssl\nrequest=url"
        "lib.request.Request('https://cve-n8n:5678/webhook/"
        "finding-notification-dispatch',data=b'{}',headers="
        "{'Content-Type':'application/json'})\ntry:\n print(u"
        "rllib.request.urlopen(request,context=ssl.create_d"
        "efault_context(cafile='/run/cve-notification/ca.cr"
        "t'),timeout=5).status)\nexcept urllib.error.HTTPErr"
        "or as error: print(error.code)\n"
    )
    assert int(execute(runtime, "cve-notification", code).strip()) in {401, 403}


def test_worker_sigkill_recovery_and_image_sources(runtime: Config) -> None:
    import hashlib
    import time

    proof = manage.directory(runtime) / "guard.ready"
    before = proof.read_text().strip()
    identity = compose(runtime, ["ps", "-q", "cve-notification"]).stdout.strip()
    run([*docker_command(), "kill", "--signal", "KILL", identity])
    compose(runtime, ["up", "-d", "cve-notification"], managed=False)
    for _ in range(50):
        value = envoy.inspect_container(identity)
        if value["State"]["Running"]:
            break
        time.sleep(0.1)
    namespace = envoy.namespace_command(
        int(value["State"]["Pid"]), ["readlink", "/proc/self/ns/net"]
    ).stdout.strip()
    if namespace != before:
        assert readiness(runtime) == 503
    manage.guard(runtime)
    compose(runtime, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-notification"])
    wait_ready(runtime)
    code = (
        "import cve_notification,hashlib,json;from pathlib "
        "import Path;p=Path(cve_notification.__file__).pare"
        "nt;print(json.dumps({f.name:hashlib.sha256(f.read_"
        "bytes()).hexdigest() for f in p.glob('*.py')}))"
    )
    actual = json.loads(execute(runtime, "cve-notification", code))
    expected = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (runtime.root / "services/notification/src/cve_notification").glob("*.py")
    }
    assert actual == expected
