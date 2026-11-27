"""Own complete stack: real protocols, native adapters, scheduler, browser and outages."""

import asyncio
import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.infrastructure.manage import compose, docker_command, run
from tests.authentication.integration.conftest import Lab
from tests.authorization.integration.conftest import actor
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.status_integration


def exec_api(config: Any, code: str) -> str:
    identity = compose(config, ["ps", "-q", "cve-api"]).stdout.strip()
    try:
        return run([*docker_command(), "exec", identity, "python", "-c", code]).stdout
    except subprocess.CalledProcessError as error:
        report = config.root / ".runtime/test-reports/phase-22-runtime-error.log"
        report.write_text(error.stderr or "")
        report.chmod(0o600)
        raise


def collect(config: Any) -> None:
    exec_api(
        config,
        (
            "import asyncio;from cve_common.config.validation i"
            "mport load_settings;from cve_api.settings import A"
            "piSettings;from cve_api.status.collector import Co"
            "llector\nasync def main():\n c=Collector(load_settin"
            "gs(ApiSettings).status);c.database.open()\n try: aw"
            "ait c.collect()\n finally: await c.database.close()"
            "\nasyncio.run(main())"
        ),
    )


async def test_complete_stack_protocols_browser_and_outages(
    upload_lab: Lab, browser: Browser
) -> None:
    from scripts.automation import manage as automation
    from scripts.cve_enricher import manage as enricher
    from scripts.cve_findings import manage as findings
    from scripts.cve_importer import manage as importer
    from scripts.cve_matcher import manage as matcher
    from scripts.dashboard.manage import activate, node
    from scripts.infrastructure import mail
    from scripts.inventory_processor import manage as inventory
    from scripts.notifications import manage as notification
    from scripts.security.manage import origin
    from scripts.services import manage as api

    config = upload_lab.config
    assert config.project.startswith("cve-db-test-")
    # The session laboratory can already contain the native FakeRelay audit row.
    # Status sampling/browser/outage checks must not add any business data.
    counts_sql = (
        "SELECT (SELECT count(*) FROM inventory.servers) AS servers,"
        "(SELECT count(*) FROM findings.findings) AS findings,"
        "(SELECT count(*) FROM automation.notification_delivery_attempts) AS attempts"
    )
    with browser.lab.owner() as c:
        counts_before = c.execute(counts_sql).fetchone()
        assert counts_before is not None
        # The browser assertions deliberately use German accessible labels.
        c.execute("UPDATE security.instance_preferences SET default_locale='de',version=version+1")
    mail.prepare(config)
    mail.start(config)
    inventory.prepare(config)
    compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-inventory"])
    importer.start(config)
    enricher.start(config)
    matcher.start(config)
    findings.start(config)
    automation.prepare(config)
    compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-event-dispatcher"])
    notification.build(config)
    notification.start(config)
    api.prepare(config)
    extra = config.directory / "status-test-override.json"
    extra.write_text(
        json.dumps({"services": {"cve-api": {"environment": {"CVE_API_STATUS__PAUSED": "false"}}}})
    )
    compose(
        config,
        ["-f", str(extra), "up", "-d", "--no-deps", "--wait", "--wait-timeout", "60", "cve-api"],
    )
    activate(config)
    collect(config)
    collect(config)
    wrong_ca = exec_api(
        config,
        (
            "import asyncio;from cve_common.config.validation i"
            "mport load_settings;from cve_api.settings import A"
            "piSettings;from cve_api.status.probes import http\n"
            "s=load_settings(ApiSettings).status;s=s.model_copy"
            "(update={'notification_ca':s.dashboard_ca});print("
            "asyncio.run(http(s,'n8n','readiness')).result)"
        ),
    ).strip()
    assert wrong_ca == "unknown", wrong_ca
    with browser.lab.owner() as c:
        count = c.execute("SELECT count(*) n FROM status.check_observations").fetchone()["n"]
        assert count > 50
        ready = c.execute(
            "SELECT result FROM status.check_observations WHERE"
            " service_id='nginx' AND check_id='readiness' ORDER"
            " BY checked_at DESC LIMIT 1"
        ).fetchone()
        assert ready["result"] == "healthy", ready
        report = {
            r["entity_id"]: r["state"]
            for r in c.execute("SELECT entity_id,state FROM status.current_states").fetchall()
        }
        assert report["postgres"] == "healthy"
        assert "envoy" not in report
        assert report["postfix"] in {"healthy", "unknown"}
    people = [
        await actor(browser),
        await actor(browser),
        await actor(browser, ("security_analyst",)),
        await actor(browser, ("viewer",)),
        await actor(browser),
    ]
    actors = []
    for p in people:
        with browser.lab.owner() as c:
            m = c.execute(
                (
                    "SELECT key_id,ciphertext,last_used_step FROM secur"
                    "ity.mfa_methods WHERE user_id=%s AND verified_at I"
                    "S NOT NULL AND revoked_at IS NULL"
                ),
                (p.id,),
            ).fetchone()
        secret = (
            base64.b32encode(
                browser.service.keyring.decrypt(p.id, m["key_id"], bytes(m["ciphertext"]))
            )
            .decode()
            .rstrip("=")
            if m
            else None
        )
        actors.append(
            {
                "name": p.name,
                "password": p.password,
                "cookie": p.cookie,
                "secret": secret,
                "step": m["last_used_step"] if m else 0,
            }
        )
    # Live history belongs to the API's in-process collector. An independent
    # diagnostic collect() persists DB observations but cannot warm that cache.
    from tests.infrastructure.client import request

    for _ in range(120):
        history = await asyncio.to_thread(
            request,
            config,
            config.values["DASHBOARD_DOMAIN"],
            path="/api/v1/status/services/api/history?check_id=readiness",
            method="GET",
            headers={"Cookie": "__Host-cve-session=" + people[0].cookie},
        )
        if history.status == 200 and json.loads(history.body)["samples"]:
            break
        await asyncio.sleep(1)
    else:
        raise AssertionError(
            "The real API status collector did not publish live history; HTTP "
            + str(history.status)
        )
    binary = node(config.root)
    env = dict(
        os.environ,
        PATH=str(binary) + os.pathsep + os.environ.get("PATH", ""),
        PLAYWRIGHT_BROWSERS_PATH=str(config.root / ".runtime/playwright"),
        CVE_E2E_URL=origin(config),
        CVE_STATUS_TEST_ACTORS=json.dumps(actors),
    )
    log = config.root / ".runtime/test-reports/phase-22-e2e.log"
    with log.open("w") as output:
        result = subprocess.run(
            [
                str(binary / "npm"),
                "--prefix",
                "services/dashboard",
                "run",
                "e2e",
                "--",
                "--config",
                "playwright.status.config.ts",
            ],
            env=env,
            cwd=config.root,
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=900,
            check=False,
        )
    assert result.returncode == 0, log.read_text()
    faults = []
    for service, key in [
        ("cve-n8n", "n8n"),
        ("cve-mail-relay", "postfix"),
    ]:
        compose(config, ["stop", service])
        try:
            if key == "postfix":
                path = config.root / ".runtime/status" / config.project / key / "observation.json"
                # Model the reporting deadline without sleeping three minutes per outage.
                code = (
                    "import json,sys;from pathlib import Path;p=Path(sy"
                    "s.argv[1]);v=json.loads(p.read_text());v['checked_"
                    "at']='2000-01-01T00:00:00Z';p.write_text(json.dump"
                    "s(v));p.chmod(0o644)"
                )
                run(["sudo", "-n", str(Path(sys.executable)), "-c", code, str(path)])
            collect(config)
            with browser.lab.owner() as c:
                state = c.execute(
                    "SELECT state FROM status.current_states WHERE entity_id=%s", (key,)
                ).fetchone()["state"]
                assert state in {"unknown", "degraded", "unavailable"}, (key, state)
                faults.append({"service": key, "state": state})
        finally:
            if key == "postfix":
                mail.start(config)
                notification.guard(config)
            else:
                compose(config, ["start", service])
                compose(config, ["up", "-d", "--wait", "--wait-timeout", "90", service])
    # Real database loss: protected health proxy and API must not report a successful state.
    compose(config, ["stop", "cve-postgres"])
    try:
        status = exec_api(
            config,
            (
                "import urllib.request,urllib.error\ntry: print(urll"
                "ib.request.urlopen('http://127.0.0.1:8000/health/r"
                "eady',timeout=5).status)\nexcept urllib.error.HTTPE"
                "rror as e: print(e.code)"
            ),
        ).strip()
        assert status == "503", status
    finally:
        compose(config, ["start", "cve-postgres"])
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
    collect(config)
    collect(config)
    compose(config, ["stop", "cve-api"])
    try:
        args = [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--cacert",
            config.values["TLS_TRUST_FILE"],
            "--resolve",
            f"{config.values['DASHBOARD_DOMAIN']}:{config.values['INGRESS_HTTPS_PORT']}:127.0.0.1",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
        ]
        address = origin(config)
        assert run([*args, address + "/status"]).stdout == "200"
        assert run([*args, address + "/api/v1/status/overview"]).stdout in {"502", "503"}
    finally:
        compose(config, ["-f", str(extra), "up", "-d", "--wait", "--wait-timeout", "60", "cve-api"])
    collect(config)
    (config.root / ".runtime/test-reports/phase-22-outages.json").write_text(
        json.dumps(
            faults
            + [
                {"service": "postgres", "state": "503"},
                {"service": "api", "state": "502/503 with static page retained"},
            ],
            indent=2,
        )
    )
    with browser.lab.owner() as c:
        assert c.execute(counts_sql).fetchone() == counts_before
    compose(config, ["stop", "cve-api"])
