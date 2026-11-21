"Safe logs/mounts, representative payloads and protected status across controller identities."

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import pytest

from scripts.infrastructure.manage import compose
from tests.infrastructure.client import request

from .conftest import Browser, call, dashboard, payload, provision, technical
from .test_acceptance import uploader

pytestmark = [pytest.mark.inventory_upload, pytest.mark.security]


async def test_logs_and_container_mounts_contain_no_credentials_or_payloads(
    browser: Browser,
) -> None:
    upload = await provision(browser)
    marker = "confidential-" + str(time.time_ns())
    raw = payload(
        upload.server["id"],
        collector={"name": "ansible", "version": "2.19", "controller_id": marker},
    )
    cfg = browser.lab.config
    result = request(
        cfg,
        domain=cfg.values["INVENTORY_DOMAIN"],
        path="/api/v1/inventories",
        method="POST",
        client="client",
        body=raw,
        headers={"Authorization": "Bearer " + upload.token, "Content-Type": "application/json"},
    )
    assert result.status == 202, result.body
    logs = compose(cfg, ["logs", "--no-color", "cve-api", "cve-nginx", "cve-postgres"]).stdout
    assert (
        upload.token not in logs
        and marker not in logs
        and "-----BEGIN CERTIFICATE-----" not in logs
    )
    names = compose(
        cfg,
        [
            "exec",
            "-T",
            "cve-api",
            "python",
            "-c",
            "from pathlib import Path; print(' '.join(p.name for p in Path('/r"
            "un/cve-api').iterdir()))",
        ],
    ).stdout
    assert "client.key" not in names and "client-ca.key" not in names


async def test_large_valid_inventory_uses_bounded_shared_pipeline(browser: Browser) -> None:
    upload = await provision(browser)
    user = await uploader(browser, upload.server["id"])
    packages = [
        {
            "name": "package-" + str(i),
            "version": "1:2.3.4-0ubuntu1~24.04.1",
            "architecture": "amd64",
            "package_manager": "dpkg",
        }
        for i in range(5000)
    ]
    raw = payload(upload.server["id"], packages={"status": "complete", "items": packages})
    began = time.monotonic()
    a = await technical(browser, upload, raw)
    technical_seconds = time.monotonic() - began
    assert a.status_code == 202, a.text
    began = time.monotonic()
    b = await dashboard(browser, user, upload.server["id"], raw)
    dashboard_seconds = time.monotonic() - began
    assert b.status_code == 202, b.text
    target = Path(".runtime/test-reports/phase-11-performance.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "packages": 5000,
                "payload_bytes": len(raw),
                "technical_seconds": technical_seconds,
                "dashboard_seconds": dashboard_seconds,
                "max_payload_bytes": 10485760,
                "worker_address_space_mib": 256,
                "worker_cpu_seconds": 12,
                "worker_wall_seconds": 15,
                "concurrent_parsers": 1,
                "api_container_mib": 512,
            },
            indent=2,
        )
        + "\n"
    )
    target.chmod(0o600)


async def test_technical_status_does_not_cross_controller_identity(browser: Browser) -> None:
    upload = await provision(browser)
    result = await technical(browser, upload, payload(upload.server["id"]))
    assert result.status_code == 202
    client = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-clients",
        {"name": "other-controller-" + str(time.time_ns())},
    )
    pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
    cert = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-clients/" + client.json()["id"] + "/certificates",
        {"certificate_pem": (pki / "client-new.crt").read_text()},
    )
    assert cert.status_code == 201, cert.text
    token = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-clients/" + client.json()["id"] + "/tokens",
        {
            "server_id": upload.server["id"],
            "certificate_id": cert.json()["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert token.status_code == 201, token.text
    r = await browser.technical_client.get(
        result.json()["status_url"],
        headers={
            "authorization": "Bearer " + token.json()["token"],
            "x-cve-inventory-certificate": quote((pki / "client-new.crt").read_text(), safe=""),
        },
    )
    assert r.status_code == 404, r.text


async def test_read_only_diagnostics_are_bounded_and_never_print_secrets(
    browser: Browser, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import sys

    from scripts.inventory import manage

    upload = await provision(browser)
    submitted = await technical(browser, upload, payload(upload.server["id"]))
    assert submitted.status_code == 202
    monkeypatch.setattr(manage, "load_config", lambda: browser.lab.config)
    capsys.readouterr()
    for action in ["contract", "mtls", "credentials", "permissions", "metrics", "submission"]:
        argv = ["inventory", action]
        if action == "submission":
            argv += ["--submission-id", submitted.json()["submission_id"]]
        monkeypatch.setattr(sys, "argv", argv)
        assert manage.main() == 0
        out = capsys.readouterr().out
        assert upload.token not in out and "certificate_pem" not in out and "payload_raw" not in out
        assert json.loads(out)["result"] == "ok"
