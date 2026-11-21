"""Version preservation, closed contracts and data quality without network access."""

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from cve_inventory.normalization import encoded, normalize, version_parts
from cve_inventory.validation import InvalidInventory, prepare, validate

ROOT = Path(__file__).resolve().parents[2]


def sample() -> dict[str, Any]:
    value: dict[str, Any] = json.loads(
        (ROOT / "contracts/inventory/examples-v1.1/valid-collect.json").read_text()
    )
    value["inventory_id"] = str(uuid4())
    value["captured_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    return value


def stored(value: dict[str, Any] | None = None) -> dict[str, Any]:
    value = value or sample()
    raw = encoded(value).encode()
    identity = uuid4()
    return {
        "payload_raw": raw,
        "payload_json": value,
        "payload_sha256": hashlib.sha256(raw).digest(),
        "canonical_sha256": hashlib.sha256(raw).digest(),
        "schema_version": value["schema_version"],
        "server_id": UUID(value["server_id"]),
        "inventory_id": UUID(value["inventory_id"]),
        "collected_at": datetime.fromisoformat(value["captured_at"]),
        "received_at": datetime.now(UTC),
        "source": "ansible_api",
        "source_identity": identity,
        "technical_principal_id": identity,
        "actor_user_id": None,
        "token_id": uuid4(),
        "certificate_id": uuid4(),
        "certificate_fingerprint": bytes(32),
        "session_reference": None,
    }


@pytest.mark.parametrize(
    ("manager", "raw", "parts"),
    [
        ("dpkg", "1:2.4.58-1ubuntu8.4", ("1", "2.4.58", "1ubuntu8.4")),
        ("dpkg", "2:6.1.0~rc1+deb12-1+b1", ("2", "6.1.0~rc1+deb12", "1+b1")),
        ("dpkg", "1.0", (None, "1.0", None)),
        ("dpkg", "1.0-a-b", (None, "1.0-a", "b")),
        ("rpm", "1:3.0.7-18.el9_5.3", ("1", "3.0.7", "18.el9_5.3")),
        ("rpm", "6.12.0~rc1^git-1.fc43", (None, "6.12.0~rc1^git", "1.fc43")),
    ],
)
def test_versions(manager: str, raw: str, parts: tuple[str | None, ...]) -> None:
    result = version_parts({"package_manager": manager, "version": raw})
    assert tuple(result[k] for k in ("epoch", "upstream_version", "release")) == parts
    assert result["normalization_status"] == "normalized"


@pytest.mark.parametrize("raw", ["a:1-2", "1.0-", "1 2-3", "", "x", "1.0-@invalid"])
def test_bad_versions(raw: str) -> None:
    assert (
        version_parts({"package_manager": "dpkg", "version": raw})["normalization_status"]
        == "invalid_version"
    )


@pytest.mark.parametrize("manager", ["apk", "pip", "npm", "other"])
def test_unknown_ecosystem(manager: str) -> None:
    assert (
        version_parts({"package_manager": manager, "version": "v1+original"})[
            "normalization_status"
        ]
        == "unknown"
    )


def test_parallel_versions_architectures_and_source() -> None:
    value = sample()
    base = value["packages"]["items"][0]
    value["packages"]["items"] = [
        base,
        base,
        {**base, "version": "2.0-1"},
        {**base, "architecture": "arm64"},
        {**base, "source_package": {"name": "source", "version": "1.0"}},
    ]
    result = validate(stored(value))
    assert len(result["packages"]) == 4
    assert result["packages"][0]["version"] in {"1:2.4.58-1ubuntu8.4", "2.0-1"}
    assert {p["architecture"] for p in result["packages"]} == {"amd64", "arm64"}


@pytest.mark.parametrize(
    "field",
    [
        "payload_sha256",
        "canonical_sha256",
        "schema_version",
        "server_id",
        "inventory_id",
        "source",
        "source_identity",
        "collected_at",
        "payload_json",
    ],
)
def test_tampered_metadata(field: str) -> None:
    row = stored()
    replacement: dict[str, Any] = {
        "payload_sha256": bytes(32),
        "canonical_sha256": bytes(32),
        "schema_version": "99",
        "server_id": uuid4(),
        "inventory_id": uuid4(),
        "source": "untrusted",
        "source_identity": uuid4(),
        "collected_at": datetime.now(UTC),
        "payload_json": {},
    }
    row[field] = replacement[field]
    with pytest.raises(InvalidInventory):
        validate(row)


@pytest.mark.parametrize("state", ["complete", "partial", "failed"])
def test_collection_quality(state: str) -> None:
    value = sample()
    value["collection_status"] = state
    if state != "complete":
        value["packages"] = {"status": "failed", "error_code": "collect_failed"}
    if state == "failed":
        for field in ("os", "services", "containers", "images"):
            value[field] = {"status": "failed", "error_code": "collect_failed"}
    data = validate(stored(value))
    assert data["eligible"] is (state == "complete")
    assert data["quality"]["collection_status"] == state


def test_future_is_historical_and_unknown_os_preserved() -> None:
    row = stored()
    value = sample()
    value["os"]["data"]["distribution"] = "Unfamiliar Linux"
    value["captured_at"] = (row["received_at"] + timedelta(seconds=60)).isoformat()
    data = normalize(value, row["received_at"])
    assert not data["eligible"]
    assert data["os"]["distribution"] == "Unfamiliar Linux"
    assert data["os_id"] is None
    assert {"unknown_distribution", "future_collection"} <= set(data["quality"]["warnings"])


def test_v1_optional_sections_and_empty_packages() -> None:
    value = sample()
    value["schema_version"] = "1.0"
    for field in ("hardware", "docker", "images", "diagnostics", "services", "containers"):
        value.pop(field, None)
    value["os"]["data"].pop("family")
    value["packages"]["items"] = []
    result = validate(stored(value))
    assert result["eligible"] and result["packages"] == []
    assert len(result["sections"]) == 4
    assert result["sections"][-1]["status"] == "not_collected"


def test_images_merge_references_and_container_resolution() -> None:
    value = sample()
    item = value["images"]["items"][0]
    value["images"]["items"].append({**item, "references": ["example:other"]})
    value["containers"]["items"] = [
        {
            "container_id": "a" * 64,
            "image_reference": "example:other",
            "image_id": item["image_id"],
            "state": "stopped",
            "collection_status": "complete",
        }
    ]
    result = validate(stored(value))
    assert len(result["images"]) == 1 and len(result["images"][0]["references"]) == 2
    assert result["containers"][0]["image_resolved"]


@pytest.mark.parametrize("name", ["inventory-v1.schema.json", "inventory-v1.1.schema.json"])
def test_packaged_contract_identical(name: str) -> None:
    assert (ROOT / "contracts/inventory" / name).read_bytes() == (
        ROOT / "services/inventory/src/cve_inventory/data" / name
    ).read_bytes()


@pytest.mark.asyncio
async def test_resource_bounded_subprocess() -> None:
    row = stored()
    assert await prepare(copy.deepcopy(row)) == validate(row)


def test_matching_event_contract() -> None:
    from cve_inventory.processing import InventoryEvent
    from jsonschema import Draft202012Validator, FormatChecker

    value = InventoryEvent(
        submission_id=uuid4(),
        server_id=uuid4(),
        snapshot_id=uuid4(),
        captured_at=datetime.now(UTC),
        collection_status="complete",
        is_current=True,
    )
    schema = json.loads((ROOT / "contracts/events/inventory-processing-v1.schema.json").read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    result = value.model_dump(mode="json")
    assert validator.is_valid(result)
    assert not validator.is_valid({**result, "payload_raw": "forbidden"})


def test_rpm_explicit_fields_and_digests() -> None:
    value = sample()
    package = {
        "name": "kernel",
        "package_manager": "rpm",
        "architecture": "aarch64",
        "version": "2:6.8.1-1.fc43",
        "epoch": "2",
        "release": "1.fc43",
    }
    value["packages"]["items"] = [package]
    value["images"]["items"][0]["repo_digests"] = ["example.test/repo@sha256:" + "b" * 64]
    normalized = validate(stored(value))
    assert normalized["packages"][0]["epoch"] == "2"
    assert normalized["packages"][0]["normalization_status"] == "normalized"
    assert "image_digest_invalid" not in normalized["quality"]["warnings"]
    result = version_parts({**package, "epoch": "3"})
    assert result["normalization_status"] == "invalid_version"


@pytest.mark.parametrize(
    "reference,repository,tag,digest",
    [
        ("registry.example:5000/team/app:v1", "registry.example:5000/team/app", "v1", None),
        ("registry.example:5000/team/app", "registry.example:5000/team/app", None, None),
        ("[2001:db8::1]:5000/team/app:v1", "[2001:db8::1]:5000/team/app", "v1", None),
        ("app@sha256:" + "a" * 64, "app", None, "sha256:" + "a" * 64),
        ("sha256:" + "a" * 64, None, None, "sha256:" + "a" * 64),
    ],
)
def test_image_reference_parts(
    reference: str, repository: str | None, tag: str | None, digest: str | None
) -> None:
    from cve_inventory.normalization import image_reference

    assert image_reference(reference) == {
        "reference": reference,
        "repository": repository,
        "tag": tag,
        "digest": digest,
    }
