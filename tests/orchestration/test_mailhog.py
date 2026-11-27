"""Stock MailHog captures both a queued UI test and the real Postfix delivery path."""

import asyncio
import json
from collections.abc import Iterator
from dataclasses import replace
from uuid import uuid4

import httpx
import pytest
import yaml

from scripts.infrastructure.manage import Config, compose, docker_command, run
from scripts.smtp.manage import process as configure_smtp
from scripts.smtp.testing import process as process_test_mail
from tests.authentication.integration.conftest import Lab
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser, isolated_upload_lab
from tests.orchestration.test_runtime import browser, eventually, platform

__all__ = ["browser", "mailhog", "platform", "upload_lab"]
pytestmark = pytest.mark.orchestration


@pytest.fixture(scope="module")
def upload_lab() -> Iterator[Lab]:
    yield from isolated_upload_lab(
        {
            "SMTP_HOST": "mailhog.cve.test",
            "SMTP_PORT": "1025",
            "SMTP_SENDER": "monitor@example.test",
            "SMTP_USERNAME": "",
            "SMTP_PASSWORD": "",
        }
    )


@pytest.fixture
def mailhog(platform: Config) -> Iterator[Config]:
    assert platform.project.startswith("cve-db-test-")
    model = yaml.safe_load((platform.root / "infrastructure/compose/mail-test.yml").read_text())
    ports = model["services"]["cve-mailhog"]["ports"]
    assert len(ports) == 1 and ports[0]["target"] == 8025
    assert ports[0]["host_ip"] == "127.0.0.1"
    # Keep the optional stock definition, with a private port unique to this test lab.
    ports[0]["published"] = int(platform.values["MAILHOG_HTTP_PORT"])
    overlay = platform.directory / "mailhog-test.compose.json"
    overlay.write_text(json.dumps(model))
    platform = replace(platform, compose_overrides=(*platform.compose_overrides, overlay))
    try:
        yield platform
    finally:
        compose(platform, ["rm", "-s", "-f", "cve-mailhog"])
        remaining = run(
            [
                *docker_command(),
                "ps",
                "-a",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + platform.project,
                "--filter",
                "label=com.docker.compose.service=cve-mailhog",
            ]
        ).stdout.strip()
        assert not remaining, "Own optional MailHog capture was not removed"


async def test_local_mailhog_compose_bootstrap_and_both_delivery_paths(
    mailhog: Config, browser: Browser
) -> None:
    platform = mailhog
    await asyncio.to_thread(
        compose,
        platform,
        ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "60", "cve-mailhog"],
    )
    await asyncio.to_thread(
        eventually,
        platform,
        "SELECT c.state='authorized' AND q.finished_at<clock_timestamp()-interval '2 seconds' "
        "AS ready FROM automation.smtp_configs c JOIN automation.n8n_queue q ON q.id=c.queue_id "
        "WHERE owner_id IS NULL ORDER BY version DESC LIMIT 1",
    )
    await asyncio.to_thread(configure_smtp, platform)
    admin = await actor(browser)
    headers = {
        "cookie": "__Host-cve-session=" + admin.cookie,
        "x-csrf-token": admin.csrf,
        "Idempotency-Key": str(uuid4()),
    }
    central = await browser.client.get("/api/v1/dashboard/administration/smtp", headers=headers)
    assert central.status_code == 200, central.text
    assert central.json()["state"] == "applied" and not central.json()["password_configured"]
    response = await browser.client.post(
        "/api/v1/dashboard/administration/smtp/test",
        headers=headers,
        json={"recipient": "test-recipient@example.test"},
    )
    assert response.status_code == 202, response.text
    identity = response.json()["id"]
    await asyncio.to_thread(
        eventually,
        platform,
        "SELECT state='authorized' AS ready FROM automation.smtp_tests WHERE id=%s",
        (identity,),
    )
    await asyncio.to_thread(process_test_mail, platform)
    result = await browser.client.get("/api/v1/dashboard/administration/smtp/test", headers=headers)
    assert result.json()["state"] == "sent", result.text
    processing = compose(platform, ["ps", "-q", "cve-processing"]).stdout.strip()
    program = (
        "from pathlib import Path;from email.message import EmailMessage;"
        "from cve_notification.smtp import Adapter;"
        "b=Path('/run/cve-notification');a=Adapter(ca=b/'smtp-ca.crt',certificate=b/'smtp-client.crt',key=b/'smtp-client.key');"
        "m=EmailMessage();m['From']='monitor@example.test';m['To']='initial@example.test';"
        "m['Subject']='MailHog relay integration';m.set_content('Local relay integration');"
        "r=a.submit(m,envelope_sender='system@cve-routing.invalid',recipients=['initial@example.test']);"
        "assert r.status=='relay_accepted',r.status"
    )
    await asyncio.to_thread(run, [*docker_command(), "exec", processing, "python", "-c", program])
    url = "http://127.0.0.1:" + platform.values["MAILHOG_HTTP_PORT"] + "/api/v2/messages"
    async with httpx.AsyncClient(trust_env=False) as client:
        for _ in range(80):
            messages = (await client.get(url)).json()
            if messages["total"] == 2:
                break
            await asyncio.sleep(0.5)
        assert messages["total"] == 2, messages
        subjects = {item["Content"]["Headers"]["Subject"][0] for item in messages["items"]}
        assert subjects == {"CVE Monitor: SMTP-Testmail", "MailHog relay integration"}
        await asyncio.to_thread(
            compose,
            platform,
            [
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                "60",
                "cve-mailhog",
            ],
        )
        restored = (await client.get(url)).json()
        assert restored["total"] == 2
    report = {
        "stock_mailhog": True,
        "compose_smtp_bootstrap": True,
        "n8n_test_mail": True,
        "postfix_to_mailhog": True,
        "capture_survives_container_recreation": True,
        "local_only_http": True,
        "external_mail_sent": False,
    }
    (platform.root / ".runtime/test-reports/mailhog.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
