"""Regression evidence for the 2026-11-25 review's correctness and budget boundaries."""

import asyncio
import threading
from pathlib import Path
from typing import Any

import pytest
from cve_automation.inventory_adapter import InventoryError, packages
from cve_automation.output import load
from cve_common.concurrency import BoundedThreads, WorkBusy
from cve_matcher.container_software import software_components
from cve_matcher.cpe import configuration
from cve_matcher.engine import EvaluationLimit, cna, purl_key, source_keys
from cve_notification.reports import affected_label


@pytest.mark.parametrize("count", [1024, 1025, 4096])
@pytest.mark.parametrize("conflict", [False, True])
def test_cna_checks_the_last_allowed_version(count: int, conflict: bool) -> None:
    component = {"vendor": "acme", "product": "app", "version": "1.0.0"}
    versions = [{"version": "0.0.0", "status": "unaffected"} for _ in range(count - 1)]
    if conflict:
        versions[0] = {"version": "1.0.0", "status": "unaffected"}
    versions.append({"version": "1.0.0", "status": "affected"})
    value = {
        "vendor": "acme",
        "product": "app",
        "defaultStatus": "unaffected",
        "versions": versions,
    }
    assert cna(component, value)[0] == ("unknown" if conflict else "affected")
    with pytest.raises(EvaluationLimit):
        cna(component, {**value, "versions": versions + versions + versions + versions + versions})


@pytest.mark.parametrize("depth", [0, 17, 31, 32])
def test_every_supported_positive_nvd_tree_has_candidate_keys(depth: int) -> None:
    cpe = "cpe:2.3:a:acme:app:1.0.0:*:*:*:*:*:*:*"
    tree: dict[str, Any] = {"cpeMatch": [{"criteria": cpe, "vulnerable": True}]}
    for _ in range(depth):
        tree = {"nodes": [tree]}
    assert configuration(tree, [{"cpe": cpe}]) == (True, True)
    assert "cpe:a:acme:app" in source_keys([{"kind": "nvd_configuration_logic", "value": [tree]}])


def test_overlong_nvd_lists_never_publish_partial_indices() -> None:
    tree: dict[str, Any] = {"nodes": [{}] * 4097}
    with pytest.raises(EvaluationLimit):
        source_keys([{"kind": "nvd_configuration_logic", "value": [tree]}])


@pytest.mark.parametrize(
    "field,other",
    [
        ("architecture", "aarch64"),
        ("type", "rpm"),
        ("source_package", "other"),
        ("source_version", "2"),
    ],
)
def test_container_identity_and_duplicate_locations(field: str, other: str) -> None:
    package = {
        "name": "app",
        "version": "1",
        "type": "deb",
        "architecture": "x86_64",
        "source_package": "app",
        "source_version": "1",
        "locations": ["/a"],
    }
    document = {
        "os": {"id": "ubuntu"},
        "packages": [package, {**package, field: other}, {**package, "locations": ["/b"]}],
    }
    entries = [
        {
            "container_id": "c",
            "image_id": "i",
            "scope": "image",
            "status": "complete",
            "document": document,
        }
    ]
    components = software_components(
        [{"container_id": "c", "image_id": "i", "state": "running"}], entries
    )
    assert len(components) == len({c["id"] for c in components}) == 2
    assert components[0]["architecture"] == "x86_64"
    assert components[0]["locations"] == ["/a", "/b"]


def test_purl_qualifiers_are_semantic_and_keep_distribution_and_architecture() -> None:
    original = "pkg:deb/debian/app@1?arch=amd64&distro=bookworm"
    assert purl_key(original) == purl_key("pkg:deb/debian/app@2?distro=bookworm&arch=amd64")
    assert purl_key(original) != purl_key(original.replace("amd64", "arm64"))
    assert purl_key(original) != purl_key(original.replace("bookworm", "bullseye"))
    assert purl_key(original + "&arch=arm64") is None


@pytest.mark.parametrize(
    "status,label",
    [
        ("affected", "Betroffen"),
        ("potentially_affected", "Möglicherweise betroffen"),
        ("unknown", "Betroffenheit unbekannt"),
        ("not_affected", "Nicht betroffen"),
        ("not_applicable", "Nicht anwendbar"),
    ],
)
def test_report_labels_preserve_technical_evidence_and_freshness(status: str, label: str) -> None:
    assert affected_label({"latest_matching_status": status, "is_stale": False}) == label
    assert (
        affected_label({"latest_matching_status": status, "is_stale": True})
        == label + " (veraltetes Ergebnis)"
    )


def test_remote_files_are_bounded_before_json_allocation(tmp_path: Path) -> None:
    path = tmp_path / "output"
    path.write_bytes(b" " * 4097)
    with pytest.raises(InventoryError, match="inventory_size"):
        load(path, 4096)
    path.write_text("[" * 49 + "0" + "]" * 49)
    with pytest.raises(InventoryError, match="inventory_depth"):
        load(path)
    fifo = tmp_path / "fifo"
    import os

    os.mkfifo(fifo)
    with pytest.raises(InventoryError):
        load(fifo)
    path.write_text('{"success":true}')
    assert load(path) == {"success": True}


def test_native_debian_source_identity_survives_the_adapter() -> None:
    value = packages(
        {},
        {"rc": 0, "stdout": "libbinary\t1:2-1ubuntu1\tamd64\tinstalled\tsource\t1:2-1ubuntu1\n"},
        "apt",
    )
    assert value["status"] == "complete"
    assert value["items"][0]["source_package"] == {"name": "source", "version": "1:2-1ubuntu1"}


async def test_cancelled_cpu_work_keeps_its_slot_until_the_thread_finishes() -> None:
    pool = BoundedThreads(1)
    started, release = threading.Event(), threading.Event()

    def slow() -> None:
        started.set()
        release.wait(5)

    caller = asyncio.create_task(pool.run(slow))
    try:
        await asyncio.to_thread(started.wait, 2)
        assert started.is_set()
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        with pytest.raises(WorkBusy):
            await pool.run(lambda: None)
    finally:
        release.set()
    for _ in range(100):
        if not pool.slots.locked():
            break
        await asyncio.sleep(0.01)
    assert await pool.run(lambda: 7) == 7


@pytest.mark.parametrize("servers,findings", [(1001, 0), (1000, 10001), (1000, 1)])
async def test_report_uses_a_global_budget_and_one_finding_query(
    monkeypatch: pytest.MonkeyPatch, servers: int, findings: int
) -> None:
    from uuid import uuid4

    from cve_notification import reports
    from cve_notification.contracts import Preferences

    report = {"id": uuid4(), "origin": "manual"}

    async def one(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return report

    async def busy(*_args: Any) -> None:
        return None

    queries: list[str] = []

    async def rows(_s: Any, sql: str, **_kwargs: Any) -> list[dict[str, Any]]:
        queries.append(sql)
        if "report_servers" in sql:
            return [
                {"id": i, "display_name": str(i), "current_snapshot": None, "captured_at": None}
                for i in range(servers)
            ]
        return [
            {
                "server_id": 0,
                "cve_id": "CVE-2026-12345",
                "status": "open",
                "current_priority": "unrated",
                "latest_matching_status": "unknown",
                "is_stale": True,
            }
            for _ in range(findings)
        ]

    monkeypatch.setattr(reports, "one", one)
    monkeypatch.setattr(reports, "busy", busy)
    monkeypatch.setattr(reports, "rows", rows)
    result = await reports.content(None, uuid4(), uuid4(), Preferences())  # type: ignore[arg-type]
    assert result is not None
    if servers > 1000 or findings > 10000:
        assert result == ([], "report_size_limit", False)
    else:
        assert any("Betroffenheit unbekannt (veraltetes Ergebnis)" in line for _, line in result[0])
    assert sum("current_findings" in query for query in queries) == (0 if servers > 1000 else 1)


async def test_keyring_failures_return_safe_503_and_a_fixed_diagnostic(caplog: Any) -> None:
    import logging

    import httpx
    from cve_api.auth.handlers import install_auth_handlers
    from cve_common.ssh_credentials import KeyringError
    from fastapi import FastAPI

    app = FastAPI()
    install_auth_handlers(app)

    @app.get("/fixture")
    async def broken() -> None:
        raise KeyringError("ssh_keyring_unavailable")

    caplog.set_level(logging.ERROR, logger="cve.auth")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://fixture"
    ) as client:
        response = await client.get("/fixture")
    assert response.status_code == 503
    assert "ssh_keyring_unavailable" not in response.text
    assert any(
        getattr(record, "error_code", None) == "vault_key_unavailable" for record in caplog.records
    )
