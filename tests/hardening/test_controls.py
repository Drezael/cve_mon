"""Negative controls for scanner evidence, resource summaries and encrypted backups."""

import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest

from scripts.hardening.backup import transform
from scripts.hardening.metrics import distribution
from scripts.hardening.supply_chain import gate

pytestmark = pytest.mark.security


def test_quantiles_are_nearest_rank_and_samples_remain_visible() -> None:
    report = distribution(list(range(1, 101)))
    assert (report["p50_ms"], report["p95_ms"], report["p99_ms"]) == (50, 95, 99)
    assert report["count"] == 100
    invalid_samples: list[list[float]] = [[], [-1], [float("nan")], [float("inf")]]
    for invalid in invalid_samples:
        with pytest.raises(ValueError):
            distribution(invalid)


@pytest.mark.parametrize("report", [{}, {"Results": []}, {"Results": None}, {"Results": [{}]}])
def test_missing_scanner_coverage_cannot_pass(report: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        gate(report)


def test_high_unfixed_and_unknown_findings_block() -> None:
    values = [
        {
            "VulnerabilityID": "TEST-23-" + severity,
            "PkgName": "synthetic",
            "InstalledVersion": "1",
            "Severity": severity,
        }
        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    ]
    findings = gate(
        {
            "Results": [
                {
                    "Target": "fixture",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Packages": [{}],
                    "Vulnerabilities": values,
                }
            ]
        }
    )
    assert {f["severity"] for f in findings} == {"HIGH", "CRITICAL", "UNKNOWN"}
    assert (
        gate(
            {
                "Results": [
                    {
                        "Target": "fixture",
                        "Class": "lang-pkgs",
                        "Type": "pip",
                        "Packages": [{}],
                        "Vulnerabilities": [],
                    }
                ]
            }
        )
        == []
    )


@pytest.mark.parametrize("damage", ["none", "flip", "truncate", "append", "wrong-key", "header"])
def test_backup_authentication_precedes_publication(tmp_path: Path, damage: str) -> None:
    key = tmp_path / "key"
    key.write_bytes(base64.b64encode(os.urandom(32)))
    key.chmod(0o600)
    source = tmp_path / "source"
    original = json.dumps({"fixture": "private synthetic evidence"}).encode() * 5000
    source.write_bytes(original)
    source.chmod(0o600)
    encrypted = tmp_path / "backup"
    transform(source, encrypted, key)
    data = encrypted.read_bytes()
    assert original[:100] not in data and encrypted.stat().st_mode & 0o077 == 0
    if damage == "flip":
        data = data[:25] + bytes([data[25] ^ 1]) + data[26:]
    if damage == "truncate":
        data = data[:-20]
    if damage == "append":
        data += b"extra"
    if damage == "header":
        data = b"BADMAGIC" + data[8:]
    encrypted.write_bytes(data)
    if damage == "wrong-key":
        key.write_bytes(base64.b64encode(os.urandom(32)))
    output = tmp_path / "restored"
    if damage == "none":
        transform(encrypted, output, key, decrypt=True)
        assert output.read_bytes() == original
        assert output.stat().st_mode & 0o077 == 0
        with pytest.raises(ValueError):
            transform(encrypted, output, key, decrypt=True)
    else:
        with pytest.raises(ValueError):
            transform(encrypted, output, key, decrypt=True)
        assert not output.exists()
    assert not list(tmp_path.glob("*.partial"))


def test_backup_rejects_symlink_and_public_key(tmp_path: Path) -> None:
    key = tmp_path / "key"
    key.write_bytes(base64.b64encode(os.urandom(32)))
    source = tmp_path / "source"
    source.write_bytes(b"synthetic")
    source.chmod(0o600)
    with pytest.raises(ValueError):
        transform(source, tmp_path / "out", key)
    key.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(OSError):
        transform(link, tmp_path / "out", key)


@pytest.mark.parametrize("service", ["cve-postgres", "cve-nginx", "cve-n8n"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("security_opt", ["no-new-privileges:true", "seccomp:unconfined"]),
        ("security_opt", ["no-new-privileges:true", "apparmor:unconfined"]),
        ("security_opt", []),
        ("devices", ["/dev/sda:/dev/sda"]),
        ("pid", "host"),
        ("ipc", "host"),
        ("uts", "host"),
        ("cgroup", "host"),
    ],
)
def test_compose_bootstrap_exceptions_do_not_disable_uniform_guards(
    service: str,
    field: str,
    value: Any,
) -> None:
    from scripts.infrastructure.manage import load_config, resolved, validate_model

    model = resolved(load_config())
    model["services"][service][field] = value
    assert validate_model(model, True)


def test_rerun_merge_preserves_unrerun_failures_and_provenance(tmp_path: Path) -> None:
    from scripts.hardening.evidence import merge_reports

    original = tmp_path / "original.xml"
    rerun = tmp_path / "rerun.xml"
    target = tmp_path / "latest.xml"
    original.write_text(
        '<testsuites><testsuite><testcase classname="c" name="one">'
        '<failure message="old"/></testcase><testcase classname="c" name="two">'
        '<failure message="still failing"/></testcase></testsuite></testsuites>'
    )
    rerun.write_text(
        '<testsuites><testsuite><testcase classname="c" name="one"/></testsuite></testsuites>'
    )
    metadata = merge_reports([original, rerun], target)
    assert metadata["distinct_cases"] == 2 and metadata["failure"] == 1
    assert metadata["sources_in_order"][0]["path"] == "original.xml"
    assert "still failing" in target.read_text() and "old" in original.read_text()
    with pytest.raises(ValueError):
        merge_reports([tmp_path / "missing"], target)


def test_api_metric_window_is_bounded_expires_and_does_not_invent_healthy_rate() -> None:
    from cve_common.http.metrics import Window

    window = Window()
    assert window.snapshot(0)["error_rate"] is None
    for i in range(10000):
        window.record(503 if i % 2 else 401, 10.0, float(i))
    assert len(window.buckets) == 60
    value = window.snapshot(9999)
    assert value["api_requests"] == 60 and value["api_errors"] == 30
    assert value["error_rate"] == 0.5 and value["api_mean_latency_ms"] == 10
    assert window.snapshot(10060)["error_rate"] is None


async def test_auth_maintenance_stops_when_driver_translates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager, suppress
    from types import SimpleNamespace
    from typing import Any, cast

    from cve_api.auth.service import AuthService
    from sqlalchemy.exc import SQLAlchemyError

    entered = asyncio.Event()
    converted = False

    @asynccontextmanager
    async def transaction(_database: object) -> AsyncIterator[None]:
        yield None

    async def execute(*_args: object, **_kwargs: object) -> None:
        nonlocal converted
        entered.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            if converted:
                raise
            converted = True
            raise SQLAlchemyError("synthetic driver cancellation conversion") from None

    service = cast(Any, object.__new__(AuthService))
    service.settings = SimpleNamespace(cleanup_seconds=0)
    service.database = object()
    monkeypatch.setattr("cve_api.auth.service.transaction", transaction)
    monkeypatch.setattr("cve_api.auth.service.execute", execute)
    task = asyncio.create_task(service._maintenance())
    try:
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=1)
        assert task in done, "maintenance must not swallow the cancellation request"
    finally:
        if not task.done():
            task.cancel()
        with suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
