"""Repository-owned HTTPS submit client against isolated Nginx/API/PostgreSQL."""

import asyncio
import base64
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from scripts.database.manage import connect
from scripts.infrastructure.manage import compose

from .conftest import Browser, call, create_server, payload, provision

pytestmark = [pytest.mark.inventory_upload, pytest.mark.security]
REPOSITORY = Path(__file__).resolve().parents[3]


def project(browser: Browser, root: Path, entries: list[dict[str, Any]]) -> dict[str, str]:
    root.mkdir(parents=True, mode=0o700)
    cfg = browser.lab.config
    targets = {}
    for item in entries:
        hostname = item.get("hostname", "target")
        directory = root / "inventory_exports" / item["server_id"]
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        output = directory / "test.json"
        output.write_bytes(base64.b64decode(item["raw"]))
        output.chmod(0o600)
        token = root / (hostname + ".token")
        token.write_text(item["token"])
        token.chmod(0o600)
        connection = root / (hostname + ".json")
        connection.write_text(
            json.dumps(
                {
                    "origin": "https://"
                    + cfg.values["INVENTORY_DOMAIN"]
                    + ":"
                    + cfg.values["INGRESS_HTTPS_PORT"],
                    "ca_file": cfg.values["TLS_TRUST_FILE"],
                    "certificate_file": item["client_cert"],
                    "key_file": item["client_key"],
                    "token_file": str(token),
                    "receipt_root": str(root / "inventory_receipts"),
                }
            )
        )
        connection.chmod(0o600)
        targets[hostname] = {"config": str(connection), "file": str(output)}
    (root / "targets.json").write_text(json.dumps(targets))
    dns = root / "test-dns"
    dns.mkdir()
    (dns / "sitecustomize.py").write_text(
        "import socket\n_original=socket.getaddrinfo\n"
        "def _resolve(host,*args,**kwargs):\n"
        "    return _original('127.0.0.1' if host=="
        + repr(cfg.values["INVENTORY_DOMAIN"])
        + " else host,*args,**kwargs)\nsocket.getaddrinfo=_resolve\n"
    )
    return {"root": str(root), "dns": str(dns)}


def run(
    local: dict[str, str], extra: dict[str, Any] | None = None, batch: bool = False
) -> subprocess.CompletedProcess[str]:
    root = Path(local["root"])
    targets = json.loads((root / "targets.json").read_text())
    value = extra or {}
    items = value.get("inventory_submit_items", []) if batch else [{"hostname": "target"}]
    results = []
    for item in items:
        target = targets[item["hostname"]]
        command = [sys.executable, "-m", "scripts.ansible.submit", "--config", target["config"]]
        if value.get("inventory_submit_action") == "status":
            submission = value.get("submission_id")
            if not submission:
                receipt = next((root / "inventory_receipts").glob("*/*.receipt.json"))
                submission = json.loads(receipt.read_text())["submission_id"]
            command += ["--status", submission]
        else:
            command += ["--file", target["file"]]
        results.append(
            subprocess.run(
                command,
                cwd=REPOSITORY,
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "PYTHONPATH": os.pathsep.join([local["dns"], str(REPOSITORY)])},
            )
        )
    return subprocess.CompletedProcess(
        args=["repository-submit"],
        returncode=int(any(r.returncode for r in results)),
        stdout="".join(r.stdout for r in results),
        stderr="".join(r.stderr for r in results),
    )


def entry(browser: Browser, upload: Any, raw: bytes, hostname: str = "target") -> dict[str, Any]:
    pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
    return {
        "hostname": hostname,
        "server_id": upload.server["id"],
        "token": upload.token,
        "client_cert": str(pki / "client.crt"),
        "client_key": str(pki / "client.key"),
        "raw": base64.b64encode(raw).decode(),
    }


async def test_real_launcher_uri_submission_duplicate_status_and_restart(
    browser: Browser, tmp_path: Path
) -> None:
    upload = await provision(browser)
    value = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "contracts/inventory/examples-v1.1/valid-collect.json"
        ).read_text()
    )
    value.update(
        server_id=upload.server["id"],
        inventory_id=str(uuid4()),
        captured_at=datetime.now(UTC).isoformat(),
    )
    raw = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    local = project(browser, tmp_path / "submit", [entry(browser, upload, raw)])
    first = await asyncio.to_thread(run, local)
    assert first.returncode == 0, first.stdout + first.stderr
    files = list((Path(local["root"]) / "inventory_receipts").glob("*/*.json"))
    assert len(files) == 1
    receipt = json.loads(files[0].read_text())
    with connect(browser.lab.config) as c:
        row = c.execute(
            "SELECT payload_raw,schema_version FROM inventory.submissions WHERE id=%s",
            (receipt["submission_id"],),
        ).fetchone()
        assert row and bytes(row["payload_raw"]) == raw and row["schema_version"] == "1.1"
    compose(browser.lab.config, ["restart", "cve-api"])
    compose(browser.lab.config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-api"])
    second = await asyncio.to_thread(run, local)
    assert second.returncode == 0, second.stdout + second.stderr
    assert '"duplicate": true' in second.stdout
    status = await asyncio.to_thread(run, local, {"inventory_submit_action": "status"})
    assert status.returncode == 0, status.stdout + status.stderr
    assert upload.token not in first.stdout + first.stderr + second.stdout + status.stdout
    assert (
        Path(local["root"]) / "inventory_exports" / upload.server["id"] / "test.json"
    ).read_bytes() == raw


async def test_real_parallel_submits_have_one_immutable_receipt(
    browser: Browser, tmp_path: Path
) -> None:
    upload = await provision(browser)
    local = project(
        browser, tmp_path / "submit", [entry(browser, upload, payload(upload.server["id"]))]
    )
    results = await asyncio.gather(asyncio.to_thread(run, local), asyncio.to_thread(run, local))
    assert all(r.returncode == 0 for r in results), [r.stdout + r.stderr for r in results]
    assert len(list((Path(local["root"]) / "inventory_receipts").glob("*/*.json"))) == 1
    with connect(browser.lab.config) as c:
        row = c.execute(
            "SELECT count(*) AS n FROM inventory.submissions WHERE server_id=%s",
            (upload.server["id"],),
        ).fetchone()
        assert row is not None and row["n"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "revoke_token",
        "expire_token",
        "disable_client",
        "revoke_certificate",
        "wrong_certificate",
        "crl_revoked_certificate",
    ],
)
async def test_actual_revocation_denies_submit_without_receipt(
    browser: Browser, tmp_path: Path, mutation: str
) -> None:
    upload = await provision(browser)
    local = project(
        browser, tmp_path / "submit", [entry(browser, upload, payload(upload.server["id"]))]
    )
    if mutation in ("wrong_certificate", "crl_revoked_certificate"):
        certificate = "client-new" if mutation == "wrong_certificate" else "revoked-client"
        values = entry(browser, upload, payload(upload.server["id"]))
        pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
        values.update(
            client_cert=str(pki / (certificate + ".crt")),
            client_key=str(pki / (certificate + ".key")),
        )
        local = project(browser, tmp_path / "alternate", [values])
    elif mutation == "expire_token":
        with browser.lab.owner() as c:
            c.execute(
                "UPDATE security.api_tokens SET created_at=clock_timestamp()-interval '2 hours',"
                "expires_at=clock_timestamp()-interval '1 second' WHERE id=%s",
                (upload.token_id,),
            )
    else:
        path = {
            "revoke_token": "admin/inventory-tokens/" + upload.token_id + "/revoke",
            "disable_client": "admin/inventory-clients/" + upload.client_id + "/disable",
            "revoke_certificate": "admin/inventory-certificates/"
            + upload.certificate_id
            + "/revoke",
        }[mutation]
        response = await call(
            browser, upload.administrator, "POST", path, {"reason": "native submit test"}
        )
        assert response.status_code == 200, response.text
    result = await asyncio.to_thread(run, local)
    assert result.returncode != 0 and not list(
        (Path(local["root"]) / "inventory_receipts").glob("*/*.json")
    )
    assert upload.token not in result.stdout + result.stderr


async def test_actual_token_rotation_keeps_inventory_context(
    browser: Browser, tmp_path: Path
) -> None:
    upload = await provision(browser)
    raw = payload(upload.server["id"])
    first = project(browser, tmp_path / "old", [entry(browser, upload, raw)])
    initial = await asyncio.to_thread(run, first)
    assert initial.returncode == 0, initial.stdout + initial.stderr
    rotated = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-tokens/" + upload.token_id + "/rotate",
        {
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "reason": "submit rotation",
        },
    )
    assert rotated.status_code == 201, "Token rotation failed"
    fresh = entry(browser, upload, raw)
    fresh["token"] = rotated.json()["token"]
    new = project(browser, tmp_path / "new", [fresh])
    repeated = await asyncio.to_thread(run, new)
    assert repeated.returncode == 0, repeated.stdout + repeated.stderr
    a = json.loads(next((Path(first["root"]) / "inventory_receipts").glob("*/*.json")).read_text())
    b = json.loads(next((Path(new["root"]) / "inventory_receipts").glob("*/*.json")).read_text())
    assert a["submission_id"] == b["submission_id"] and a["idempotency_key"] == b["idempotency_key"]


async def test_actual_certificate_rotation_retains_idempotent_context(
    browser: Browser, tmp_path: Path
) -> None:
    upload = await provision(browser)
    raw = payload(upload.server["id"])
    first = project(browser, tmp_path / "old", [entry(browser, upload, raw)])
    initial = await asyncio.to_thread(run, first)
    assert initial.returncode == 0, initial.stdout + initial.stderr
    pki = Path(browser.lab.config.values["TLS_CERT_FILE"]).parent
    certificate = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-clients/" + upload.client_id + "/certificates",
        {"certificate_pem": (pki / "client-new.crt").read_text()},
    )
    assert certificate.status_code == 201, certificate.text
    rotated = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-tokens/" + upload.token_id + "/rotate",
        {
            "certificate_id": certificate.json()["id"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "reason": "certificate rotation",
        },
    )
    assert rotated.status_code == 201, "Token rotation failed"
    fresh = entry(browser, upload, raw)
    fresh.update(
        token=rotated.json()["token"],
        client_cert=str(pki / "client-new.crt"),
        client_key=str(pki / "client-new.key"),
    )
    new = project(browser, tmp_path / "new", [fresh])
    repeated = await asyncio.to_thread(run, new)
    assert repeated.returncode == 0, repeated.stdout + repeated.stderr
    a = json.loads(next((Path(first["root"]) / "inventory_receipts").glob("*/*.json")).read_text())
    b = json.loads(next((Path(new["root"]) / "inventory_receipts").glob("*/*.json")).read_text())
    assert a["submission_id"] == b["submission_id"]


@pytest.mark.parametrize("deny_second", [False, True])
async def test_native_explicit_batch_isolates_server_tokens_and_outcomes(
    browser: Browser, tmp_path: Path, deny_second: bool
) -> None:
    upload = await provision(browser)
    second = await create_server(browser, upload.administrator)
    token = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-clients/" + upload.client_id + "/tokens",
        {
            "server_id": second["id"],
            "certificate_id": upload.certificate_id,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert token.status_code == 201, token.text
    a = entry(browser, upload, payload(upload.server["id"]), "host-a")
    b = {
        **a,
        "hostname": "host-b",
        "server_id": second["id"],
        "token": upload.token if deny_second else token.json()["token"],
        "raw": base64.b64encode(payload(second["id"])).decode(),
    }
    local = project(browser, tmp_path / "batch", [a, b])
    requests = [
        {"hostname": "host-a", "inventory_file": "test.json"},
        {"hostname": "host-b", "inventory_file": "test.json"},
    ]
    if deny_second:
        requests.reverse()  # A failing first request must not prevent the next success.
    result = await asyncio.to_thread(run, local, {"inventory_submit_items": requests}, True)
    assert (result.returncode != 0) == deny_second, result.stdout + result.stderr
    files = list((Path(local["root"]) / "inventory_receipts").glob("*/*.json"))
    assert len(files) == (1 if deny_second else 2)
    assert upload.token not in result.stdout and token.json()["token"] not in result.stdout


async def test_native_status_rejects_foreign_server_submission(
    browser: Browser, tmp_path: Path
) -> None:
    upload = await provision(browser)
    first = project(
        browser, tmp_path / "first", [entry(browser, upload, payload(upload.server["id"]))]
    )
    sent = await asyncio.to_thread(run, first)
    assert sent.returncode == 0, sent.stdout + sent.stderr
    submission = json.loads(
        next((Path(first["root"]) / "inventory_receipts").glob("*/*.json")).read_text()
    )["submission_id"]
    second = await create_server(browser, upload.administrator)
    token = await call(
        browser,
        upload.administrator,
        "POST",
        "admin/inventory-clients/" + upload.client_id + "/tokens",
        {
            "server_id": second["id"],
            "certificate_id": upload.certificate_id,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    assert token.status_code == 201
    value = entry(browser, upload, payload(second["id"]))
    value.update(server_id=second["id"], token=token.json()["token"])
    other = project(browser, tmp_path / "other", [value])
    result = await asyncio.to_thread(
        run, other, {"inventory_submit_action": "status", "submission_id": submission}
    )
    assert result.returncode != 0 and '"http_status": 404' in result.stdout
    assert not list((Path(other["root"]) / "inventory_receipts").glob("*/*.json"))
