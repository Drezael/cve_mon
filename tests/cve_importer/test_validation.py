"""Closed source versions, full original data, offline schemas and bounded archives."""

import json
import stat
import zipfile
from pathlib import Path
from typing import Any

import pytest
from cve_importer.contracts import Configuration, ImportFailure
from cve_importer.validation import archive_batch, archive_stream, decode, record, validator

from tests.cve_importer.fixtures import catalog, cve, nvd, osv, ubuntu

pytestmark = [pytest.mark.cve_importer, pytest.mark.domain]


@pytest.mark.parametrize("version", ["5.0", "5.1", "5.1.0", "5.1.1", "5.2", "5.2.0"])
@pytest.mark.parametrize("state", ["PUBLISHED", "REJECTED"])
def test_cve_versions_and_status(version: str, state: str) -> None:
    value = cve(version, state)
    result = record("cve_list", value)
    assert result["original_json"] == value
    assert result["status"] == ("active" if state == "PUBLISHED" else "rejected")


@pytest.mark.parametrize(
    "source,value", [("nvd", nvd()), ("cisa_kev", catalog()), ("ubuntu", ubuntu()), ("osv", osv())]
)
def test_other_sources(source: str, value: dict[str, Any]) -> None:
    assert record(source, value)["original_json"] == value


@pytest.mark.parametrize("version", ["6.0", "5.3.0", "5.1.9", "4.0", ""])
def test_unknown_cve_version(version: str) -> None:
    with pytest.raises(ImportFailure, match="unsupported_cve_version"):
        record("cve_list", cve(version))


@pytest.mark.parametrize(
    "raw",
    [b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff", b'{"x":"\\u0000"}', b"[" * 70 + b"0" + b"]" * 70],
)
def test_strict_json(raw: bytes) -> None:
    with pytest.raises(ImportFailure):
        decode(raw, 1048576)


@pytest.mark.parametrize(
    "source,value", [("osv", osv(withdrawn=True)), ("ubuntu", ubuntu("USN-1000-1"))]
)
def test_advisory_identity_is_not_cve(source: str, value: dict[str, Any]) -> None:
    result = record(source, value)
    assert result["external_id"] == value["id"]
    if source == "osv":
        assert result["status"] == "withdrawn" and len(result["identifiers"]) == 3


@pytest.mark.parametrize(
    "name", ["cve-5.0", "cve-5.1", "cve-5.1.1", "cve-5.2.0", "nvd", "osv", "kev", "ubuntu"]
)
def test_schemas_are_offline(name: str) -> None:
    assert validator(name)


@pytest.mark.parametrize(
    "name",
    [
        "../CVE-2026-12345.json",
        "/CVE-2026-12345.json",
        "a\\CVE-2026-12345.json",
        "C:/CVE-2026-12345.json",
    ],
)
def test_traversal_archive(tmp_path: Path, name: str) -> None:
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(name, json.dumps(cve()))
    with pytest.raises(ImportFailure):
        archive_batch(path, "cve_list", 0, Configuration())


def test_archive_symlink_and_ratio(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    info = zipfile.ZipInfo("CVE-2026-12345.json")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, "/etc/passwd")
    with pytest.raises(ImportFailure):
        archive_batch(path, "cve_list", 0, Configuration())
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("CVE-2026-12345.json", "A" * 100000)
    with pytest.raises(ImportFailure):
        archive_batch(path, "cve_list", 0, Configuration(max_ratio=2))


@pytest.mark.asyncio
async def test_archive_process_batches_and_cleanup(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w") as z:
        for i in range(3):
            z.writestr(
                f"CVE-2026-{12345 + i}.json", json.dumps(cve(identifier=f"CVE-2026-{12345 + i}"))
            )
    batches = [
        page async for page, _ in archive_stream(path, "cve_list", 0, Configuration(batch_size=2))
    ]
    assert [len(p["records"]) for p in batches] == [2, 1] and batches[-1]["done"]


def test_vendor_schema_integrity() -> None:
    import hashlib
    from importlib.resources import files

    root = files("cve_importer").joinpath("data")
    for item in json.loads(root.joinpath("schemas.json").read_text()):
        actual = hashlib.sha256(root.joinpath(item["file"]).read_bytes()).hexdigest()
        assert item["sha256"] == "sha256:" + actual


def test_cna_and_adp_containers_preserved() -> None:
    value = cve("5.2.0")
    provider = value["containers"]["cna"]["providerMetadata"]
    value["containers"]["adp"] = [
        {
            "providerMetadata": provider,
            "descriptions": [{"lang": "en", "value": "Additional program data"}],
        }
    ]
    assert record("cve_list", value)["original_json"]["containers"] == value["containers"]


@pytest.mark.parametrize(
    "offset,limit,total,entries",
    [(0, 20, 2, []), (2, 20, 5, [{}]), (0, 20, True, []), (-1, 20, 2, [{}, {}])],
)
def test_pagination_gap_is_not_success(
    offset: int, limit: int, total: int, entries: list[Any]
) -> None:
    from cve_importer.adapters import pagination

    value = {"offset": 0, "limit": 20, "total_results": total, "cves": entries}
    with pytest.raises(ImportFailure):
        pagination(value, "cves", offset, limit, None)


async def test_nested_cve_archive_and_duplicate_identity(tmp_path: Path) -> None:
    import io

    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as z:
        z.writestr("CVE-2026-12345.json", json.dumps(cve()))
    path = tmp_path / "nested.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("all.zip", data.getvalue())
    pages = [value async for value, _ in archive_stream(path, "cve_list", 0, Configuration())]
    assert len(pages[0]["records"]) == 1 and pages[0]["done"]
    large = io.BytesIO()
    with zipfile.ZipFile(large, "w") as z:
        z.writestr("CVE-2026-12345.json", b"A" * 1100000)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("all.zip", large.getvalue())
    with pytest.raises(ImportFailure, match="scratch_quota"):
        await anext(archive_stream(path, "cve_list", 0, Configuration(scratch_limit=1048576)))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a/CVE-2026-12345.json", json.dumps(cve()))
        z.writestr("b/CVE-2026-12345.json", json.dumps(cve()))
    with pytest.raises(ImportFailure, match="archive_duplicate_identity"):
        await anext(archive_stream(path, "cve_list", 0, Configuration()))


@pytest.mark.parametrize(
    "raw",
    [
        b"2026-11-07T12:00:00Z,GHSA-test,third",
        b"not-a-time,GHSA-test",
        b"2026-11-07T12:00:00Z,../bad",
        b"2026-11-07T12:00:00Z,GHSA-test\n2026-11-07T13:00:00Z,GHSA-other",
        b"2026-11-07T12:00:00Z," + b"x" * 2048,
    ],
)
async def test_osv_index_isolated_rejection(tmp_path: Path, raw: bytes) -> None:
    from datetime import UTC, datetime

    from cve_importer.validation import index_stream

    path = tmp_path / "index.csv"
    path.write_bytes(raw)
    with pytest.raises(ImportFailure):
        await anext(
            index_stream(
                path,
                0,
                Configuration(),
                datetime(2026, 11, 6, tzinfo=UTC),
                datetime(2026, 11, 8, tzinfo=UTC),
            )
        )


@pytest.mark.parametrize("version", ["5.1", "5.1.0", "5.1.1"])
def test_cve_51_uses_compatible_official_patch_schema(version: str) -> None:
    value = cve(version=version)
    value["containers"]["cna"]["cpeApplicability"] = []
    result = record("cve_list", value)
    assert result["source_version"] == version
    assert result["original_json"] == value
    value["containers"]["cna"]["cpeApplicability"] = "invalid"
    with pytest.raises(ImportFailure):
        record("cve_list", value)
