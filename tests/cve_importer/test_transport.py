"""Closed egress, credentials, quotas and bounded retry contracts."""

import json
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from cve_importer.contracts import Configuration, ImportFailure
from cve_importer.service import proof
from cve_importer.transport import Transport, allowed

from tests.cve_importer.test_pipeline import wire_response

pytestmark = pytest.mark.cve_importer


@pytest.mark.parametrize(
    "url",
    [
        "http://services.nvd.nist.gov/rest/json/cves/2.0",
        "https://services.nvd.nist.gov.evil.test/rest/json/cves/2.0",
        "https://u:p@services.nvd.nist.gov/rest/json/cves/2.0",  # pragma: allowlist secret
        "https://127.0.0.1/rest/json/cves/2.0",
        "https://169.254.169.254/latest/meta-data",
        "https://services.nvd.nist.gov:8443/rest/json/cves/2.0",
        "https://services.nvd.nist.gov/rest/json/cves/2.0#fragment",
        "https://services.nvd.nist.gov/rest/json/cves/2.0/%2e%2e/other",
        "https://services.nvd.nist.gov/other",
        "https://ubuntu.com/security/cves.json",
        "https://services.nvd.nist.gov/rest/json/cves/2.0\\other",
    ],
)
def test_forbidden_source_urls(url: str) -> None:
    with pytest.raises(ImportFailure):
        allowed("nvd", url)


def test_redirect_only_hosts_and_source_paths() -> None:
    cdn = "https://release-assets.githubusercontent.com/github-production-release-asset/123/x"
    with pytest.raises(ImportFailure):
        allowed("cve_list", cdn)
    assert allowed("cve_list", cdn, redirect=True) == cdn
    with pytest.raises(ImportFailure):
        allowed("cve_list", "https://github.com/other/project/releases/download/x")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"enabled": ["nvd", "nvd"]},
        {"osv_ecosystems": ["arbitrary"]},
        {"batch_size": 1001},
        {"request_attempts": 4},
        {"nvd_delay": 0},
        {"unknown": True},
    ],
)
def test_configuration_closed(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        Configuration.model_validate(kwargs)


def test_egress_proof_is_private_namespace_bound(tmp_path: Path) -> None:
    path = tmp_path / "ready"
    path.write_text(os.readlink("/proc/self/ns/net"))
    path.chmod(0o600)
    assert proof(path)
    path.chmod(0o644)
    assert not proof(path)
    path.chmod(0o600)
    path.write_text("net:[1]")
    assert not proof(path)
    path.unlink()
    path.symlink_to("/proc/self/ns/net")
    assert not proof(path)


async def test_nvd_budget_and_key_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "key"
    key.write_text("synthetic-nvd-test-key")
    key.chmod(0o600)
    seen: list[httpx.Request] = []
    delays = []

    async def reserve(source: str, seconds: float) -> float:
        delays.append((source, seconds))
        return 0

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return wire_response(200, content=b"{}", headers={"Content-Type": "application/json"})

    for keyed in [False, True]:
        transport = Transport(
            Configuration(nvd_delay=0.65),
            tmp_path / ("yes" if keyed else "no"),
            nvd_key_file=key if keyed else None,
            reserve=reserve,
            client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
        )
        try:
            await transport.fetch(
                "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0", uuid4()
            )
            await transport.fetch("ubuntu", "https://ubuntu.com/security/cves.json", uuid4())
        finally:
            await transport.close()
    assert delays[0] == ("nvd", 6.1) and delays[2] == ("nvd", 0.65)
    assert "apiKey" not in seen[0].headers and seen[2].headers["apiKey"] == key.read_text()
    assert "apiKey" not in seen[1].headers and "apiKey" not in seen[3].headers


@pytest.mark.parametrize(
    "case", ["redirect", "size", "encoding", "type", "hash", "secret", "quota"]
)
async def test_download_security(tmp_path: Path, case: str) -> None:
    body = b"{}"
    headers = {"Content-Type": "application/json"}
    status = 200
    if case == "redirect":
        status, headers = 302, {"Location": "https://127.0.0.1/private"}
    elif case == "size":
        headers["Content-Length"] = "99999999999"
    elif case == "encoding":
        headers["Content-Encoding"] = "gzip"
    elif case == "type":
        headers["Content-Type"] = "text/html"
    elif case == "secret":
        body = b'{"x":"synthetic-nvd-test-key"}'
    elif case == "quota":
        body = b"x" * 1100000

    def respond(request: httpx.Request) -> httpx.Response:
        return wire_response(status, content=body, headers=headers)

    key = tmp_path / "key"
    key.write_text("synthetic-nvd-test-key")
    key.chmod(0o600)
    transport = Transport(
        Configuration(scratch_limit=1048576),
        tmp_path / "scratch",
        nvd_key_file=key,
        client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )
    try:
        with pytest.raises(ImportFailure):
            await transport.fetch(
                "nvd",
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                uuid4(),
                expected="0" * 64 if case == "hash" else None,
            )
        assert not list((tmp_path / "scratch").rglob("*.part"))
    finally:
        await transport.close()


async def test_retry_after_never_retries_early(tmp_path: Path) -> None:
    calls = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return wire_response(429, headers={"Retry-After": "3600"})

    transport = Transport(
        Configuration(max_retry_delay=1),
        tmp_path,
        client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )
    try:
        with pytest.raises(ImportFailure, match="retry_after_exceeds_budget"):
            await transport.fetch("ubuntu", "https://ubuntu.com/security/cves.json", uuid4())
        assert len(calls) == 1  # no early retry when Retry-After exceeds the run budget
    finally:
        await transport.close()


async def test_cache_rechecks_original_digest(tmp_path: Path) -> None:
    calls = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return wire_response(
            200, content=json.dumps({"fixture": 1}), headers={"Content-Type": "application/json"}
        )

    transport = Transport(
        Configuration(), tmp_path, client=httpx.AsyncClient(transport=httpx.MockTransport(respond))
    )
    try:
        run_id = uuid4()
        url = "https://ubuntu.com/security/cves.json"
        first = await transport.fetch("ubuntu", url, run_id)
        assert (await transport.fetch("ubuntu", url, run_id)).sha256 == first.sha256
        assert len(calls) == 1
        first.path.write_bytes(b"{}")
        with pytest.raises(ImportFailure, match="artifact_hash_mismatch"):
            await transport.fetch("ubuntu", url, run_id)
    finally:
        await transport.close()


@pytest.mark.parametrize("case", ["symlink", "permissions"])
async def test_git_cache_exclusion_rejects_unsafe_directory(tmp_path: Path, case: str) -> None:
    scratch = tmp_path / "scratch"
    transport = Transport(Configuration(), scratch)
    try:
        transport.directory(uuid4())
        git = scratch / "git"
        if case == "symlink":
            target = tmp_path / "external"
            target.mkdir(mode=0o700)
            git.symlink_to(target, target_is_directory=True)
        else:
            git.mkdir(mode=0o755)
            git.chmod(0o755)
        with pytest.raises(ImportFailure, match="unsafe_cache_directory"):
            transport.usage()
    finally:
        await transport.close()
