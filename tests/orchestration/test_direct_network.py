"""Direct Git/HTTPS and per-user SMTP work with no outbound proxy container."""

import asyncio
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest

from scripts.database import manage as db
from scripts.infrastructure import mail
from scripts.infrastructure.manage import Config, docker_command, run
from scripts.notifications.manage import directory
from scripts.smtp.manage import process, reload_postfix
from tests.authorization.integration.conftest import actor
from tests.infrastructure.envoy.conftest import PYTHON_IMAGE
from tests.inventory_upload.integration.conftest import Browser
from tests.orchestration.test_runtime import browser, eventually, platform, upload_lab

__all__ = ["platform", "browser", "upload_lab"]
pytestmark = pytest.mark.orchestration


def containers(config: Config) -> list[dict[str, Any]]:
    ids = run(
        [
            *docker_command(),
            "ps",
            "-q",
            "--filter",
            "label=com.docker.compose.project=" + config.project,
        ]
    ).stdout.split()
    return list(json.loads(run([*docker_command(), "inspect", *ids]).stdout))


async def test_direct_https_git_and_independent_smtp_profiles(
    platform: Config, browser: Browser, tmp_path: Path
) -> None:
    initial = containers(platform)
    assert not any(
        v["Config"]["Labels"].get("com.docker.compose.service") == "cve-egress-proxy"
        for v in initial
    )
    processing = next(
        v
        for v in initial
        if v["Config"]["Labels"]["com.docker.compose.service"] == "cve-processing"
    )["Id"]
    # Native Git uses its actual verified HTTPS transport; no clone/import or source update.
    git = run(
        [
            *docker_command(),
            "exec",
            processing,
            "git",
            "-c",
            "http.proxy=",
            "-c",
            "http.sslVerify=true",
            "ls-remote",
            "https://github.com/CVEProject/cvelistV5.git",
            "HEAD",
        ]
    ).stdout
    assert git.strip().endswith("HEAD") and len(git.split()[0]) == 40
    check = (
        "async def check():\n"
        " c=ServiceClient({'github':'https://api.github.com'},external=True,timeout=15)\n"
        " r=await c.request('GET','github','/repos/CVEProject/cvelistV5')\n"
        " assert r.status_code==200,r.status_code\n await c.close()\n"
    )
    program = (
        "import asyncio,os;from cve_common.http.client import ServiceClient;"
        "os.environ['HTTPS_PROXY']='http://missing-proxy.invalid:3128';"
        "os.environ['HTTP_PROXY']='http://missing-proxy.invalid:3128';exec("
        + repr(check)
        + ");asyncio.run(check())"
    )
    run([*docker_command(), "exec", processing, "python", "-c", program])
    # Both profiles now share the outbound bridge as well as their private bridges.
    # Docker DNS may choose any shared address; fixed health bridges must still work.
    bridge_check = (
        "async def check():\n"
        " for dimension in ('live','ready'):\n"
        "  r=await n8n_probe(Path('/run/cve-notification/ca.crt'),dimension)\n"
        "  assert json.loads(r.body)['status'] in {'alive','ready'},r.body\n"
    )
    run(
        [
            *docker_command(),
            "exec",
            processing,
            "python",
            "-c",
            "import asyncio,json;from pathlib import Path;"
            "from cve_notification.health import n8n_probe;exec("
            + repr(bridge_check)
            + ");asyncio.run(check())",
        ]
    )
    people = [
        await actor(browser),
        await actor(browser, ("viewer",)),
        await actor(browser, ("viewer",)),
    ]
    profiles = []
    hosts = [
        "smtp.direct-one.example.test",
        "smtp.direct-two.example.test",
        "smtp.direct-one.example.test",
    ]
    for index, (person, host) in enumerate(zip(people, hosts, strict=True)):
        password = secrets.token_urlsafe(32)
        response = await browser.client.put(
            "/api/v1/dashboard/notifications/mail",
            headers={
                "cookie": "__Host-cve-session=" + person.cookie,
                "x-csrf-token": person.csrf,
                "Idempotency-Key": str(uuid4()),
            },
            json={
                "version": 0,
                "mode": "custom",
                "enabled": True,
                "host": host,
                "port": 587,
                "sender": "shared@example.test",
                "recipients": ["one@example.test", "two@example.test"],
                "username": "account" + str(index),
                "password": password,
            },
        )
        assert response.status_code == 202, response.text
        identity = response.json()["id"]
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT c.state='authorized' AND q.finished_at<clock_timestamp()-interval"
            " '2 seconds' AS ready FROM automation.smtp_configs c JOIN "
            "automation.n8n_queue q ON q.id=c.queue_id WHERE c.id=%s",
            (identity,),
        )
        await asyncio.to_thread(process, platform)
        with db.connect(platform) as s:
            result = s.execute(
                "SELECT state,error_code FROM automation.smtp_configs WHERE id=%s", (identity,)
            ).fetchone()
            assert result and result["state"] == "applied", result
        profiles.append(
            {
                "owner": str(person.id),
                "host": host,
                "username": "account" + str(index),
                "password": password,
            }
        )
    person = people[0]
    response = await browser.client.post(
        "/api/v1/dashboard/notifications/mail/test",
        headers={
            "cookie": "__Host-cve-session=" + person.cookie,
            "x-csrf-token": person.csrf,
            "Idempotency-Key": str(uuid4()),
        },
        json={},
    )
    assert response.status_code == 202, response.text
    test_id = response.json()["id"]
    await asyncio.to_thread(
        eventually,
        platform,
        "SELECT state='authorized' AS ready FROM automation.smtp_tests WHERE id=%s",
        (test_id,),
    )
    await asyncio.to_thread(deliver_to_private_providers, platform, processing, profiles, tmp_path)
    with db.connect(platform) as session:
        test_result = session.execute(
            "SELECT state FROM automation.smtp_tests WHERE id=%s", (test_id,)
        ).fetchone()
        assert test_result and test_result["state"] == "sent"

    after = containers(platform)
    assert {v["Id"]: v["State"]["StartedAt"] for v in after} == {
        v["Id"]: v["State"]["StartedAt"] for v in initial
    }
    assert not mail.queue(platform)
    report = {
        "git_verified_https": True,
        "https_ignores_proxy_environment": True,
        "smtp_providers": 2,
        "smtp_user_profiles": 3,
        "n8n_test_mail": True,
        "same_provider_separate_accounts": True,
        "same_visible_sender": True,
        "recipients_per_message": 2,
        "external_mail_sent": False,
        "container_ids_and_start_times_unchanged": True,
        "proxy_containers": 0,
    }
    (platform.root / ".runtime/test-reports/direct-outbound-network.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )


def deliver_to_private_providers(
    config: Config, processing: str, profiles: list[dict[str, str]], temporary: Path
) -> None:
    base = mail.directory(config)
    sinks = {}
    try:
        for index, host in enumerate(sorted({p["host"] for p in profiles})):
            files = temporary / str(index)
            files.mkdir(mode=0o755)
            name = "direct-upstream-" + str(index)
            mail.certificate(base / "pki", name, "upstream-ca", host)
            shutil.copyfile(base / "pki" / (name + ".crt"), files / "upstream.crt")
            shutil.copyfile(base / "pki/private" / (name + ".key"), files / "upstream.key")
            accounts = {p["username"]: p["password"] for p in profiles if p["host"] == host}
            for filename, text in [
                ("smtp-accounts.json", json.dumps(accounts)),
                ("smtp_username", next(iter(accounts))),
                ("smtp_password", next(iter(accounts.values()))),
            ]:
                path = files / filename
                path.write_text(text + "\n")
                path.chmod(0o600)
            shutil.copyfile(
                config.root / "tests/infrastructure/mail/fixtures/smarthost.py",
                files / "smarthost.py",
            )
            shutil.copyfile(
                config.root / "tests/infrastructure/envoy/fixtures/servers.py", files / "base.py"
            )
            sink = config.project + "-direct-provider-" + str(index)
            run(
                [
                    *docker_command(),
                    "run",
                    "-d",
                    "--name",
                    sink,
                    "--network",
                    config.project + "_cve_outbound",
                    "--network-alias",
                    host,
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
            sinks[host] = sink
            for _ in range(40):
                ready = subprocess.run(
                    [*docker_command(), "exec", sink, "test", "-f", "/tmp/fixture-ready"],
                    check=False,
                    capture_output=True,
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("Private SMTP fixture did not become ready")
        shutil.copyfile(base / "pki/upstream-ca.crt", base / "state/upstream-ca.crt")
        reload_postfix(config)
        routes = json.loads((directory(config) / "smtp-delivery.json").read_text())
        for profile in profiles:
            alias = routes[profile["owner"]]["envelope_sender"]
            code = (
                "from pathlib import Path;from email.message import EmailMessage;from"
                " cve_notification.smtp import Adapter;"
                "b=Path('/run/cve-notification');a=Adapter(ca=b/'smtp-ca.crt',certificate=b/'smtp-client.crt',key=b/'smtp-client.key');"
                "m=EmailMessage();m['From']='shared@example.test';m['To']='one@example.test,"
                " two@example.test';m['Subject']='Direct isolated "
                "test';m.set_content('Private fixture');"
                "result=a.submit(m,envelope_sender="
                + repr(alias)
                + ",recipients=['one@example.test','two@example.test']);"
                "assert result.status=='relay_accepted',result.status"
            )
            run([*docker_command(), "exec", processing, "python", "-c", code])
        # Only fixture DNS and its CA are substituted; use the real controller,
        # saved encrypted credentials, SMTP authentication, STARTTLS and DATA.
        from scripts.smtp.testing import process as process_test

        addresses = {}
        for host, sink in sinks.items():
            inspected = json.loads(run([*docker_command(), "inspect", sink]).stdout)[0]
            addresses[host] = inspected["NetworkSettings"]["Networks"][
                config.project + "_cve_outbound"
            ]["IPAddress"]
        resolve = socket.getaddrinfo
        context = ssl.create_default_context(cafile=str(base / "pki/upstream-ca.crt"))

        def fixture_dns(host: str, *args: Any, **kwargs: Any) -> Any:
            return resolve(addresses.get(host, host), *args, **kwargs)

        with (
            patch("socket.getaddrinfo", side_effect=fixture_dns),
            patch("scripts.smtp.testing.ssl.create_default_context", return_value=context),
        ):
            process_test(config)
        for host, sink in sinks.items():
            expected = {p["username"] for p in profiles if p["host"] == host}
            program = "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/control').read().decode())"
            message_count = len(expected) + int(host == profiles[0]["host"])
            for _ in range(160):
                result = json.loads(
                    run([*docker_command(), "exec", sink, "python", "-c", program]).stdout
                )
                if len(result["messages"]) >= message_count:
                    break
                time.sleep(0.25)
            else:
                raise AssertionError("Direct SMTP provider did not receive all test messages")
            assert len(result["messages"]) == message_count
            assert set(result["authenticated_users"]) == expected
            assert result["sni"] and all(name == host for name in result["sni"])
            assert result["counters"].get("auth_before_tls", 0) == 0
            for message in result["messages"]:
                assert message["sender"] == "shared@example.test"
                assert message["recipients"] == ["one@example.test", "two@example.test"]
        for _ in range(30):
            if not mail.queue(config):
                break
            time.sleep(0.2)
    finally:
        for sink in sinks.values():
            subprocess.run([*docker_command(), "rm", "-f", sink], check=False, capture_output=True)
