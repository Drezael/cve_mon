"Authoritative schema, exact raw hashes, canonical identity and hostile JSON bounds."

import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cve_api.inventories.errors import UploadError
from cve_api.inventories.parser import validate
from cve_api.technical_auth.schemas import CertificateCreate, TokenCreate
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[3]


def valid() -> dict[str, Any]:
    value = json.loads((ROOT / "contracts/inventory/examples/valid-ubuntu.json").read_text())
    value["captured_at"] = datetime.now(UTC).isoformat()
    return dict(value)


def test_packaged_schema_is_exact_authoritative_contract() -> None:
    assert (
        files("cve_api.inventories").joinpath("data/inventory-v1.schema.json").read_bytes()
        == (ROOT / "contracts/inventory/inventory-v1.schema.json").read_bytes()
    )


def test_raw_bytes_hash_and_canonical_identity_are_separate() -> None:
    value = valid()
    first = json.dumps(value).encode()
    second = json.dumps(value, indent=2, sort_keys=True).encode()
    a, b = validate(first), validate(second)
    assert a.payload_sha256 == hashlib.sha256(first).digest() != b.payload_sha256
    assert a.canonical_sha256 == b.canonical_sha256
    assert a.server_id == b.server_id


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"null",
        b"[]",
        b"\xff",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":1e999}',
        b'{"a":"\\ud800"}',
        b'{"a":' + b"1" * 5000 + b"}",
        b"\xef\xbb\xbf{}",
    ],
)
def test_malformed_json_and_nonstandard_values(raw: bytes) -> None:
    with pytest.raises(UploadError):
        validate(raw)


@pytest.mark.parametrize(
    "field",
    [
        "group_id",
        "group_ids",
        "primary_group_id",
        "group_sort_order",
        "display_order",
        "groupIds",
        "primary-group-id",
        "display.Order",
        "exposure",
        "criticality",
        "acl",
        "register_server",
    ],
)
def test_structural_admin_injection_is_rejected_at_any_depth(field: str) -> None:
    value = valid()
    value["packages"]["items"][0]["nested"] = [{field: "bad"}]
    with pytest.raises(UploadError) as e:
        validate(json.dumps(value).encode())
    assert e.value.status == 422


def test_words_in_package_names_are_not_classified_as_control_fields() -> None:
    value = valid()
    value["packages"]["items"][0]["name"] = "group-display_order-package"
    assert validate(json.dumps(value).encode())


@pytest.mark.parametrize(
    "patch",
    [
        {"server_id": str(uuid4()).upper()},
        {"schema_version": "2.0"},
        {"captured_at": "not-a-time"},
        {"captured_at": "2026-01-01T00:00:00"},
        {"unexpected": 1},
        {"inventory_id": 12},
        {"os": {}},
        {"collector": {"name": "invented", "version": "1"}},
    ],
)
def test_schema_version_types_fields_and_formats(patch: dict[str, Any]) -> None:
    value = valid()
    value.update(patch)
    with pytest.raises(UploadError) as e:
        validate(json.dumps(value).encode())
    assert e.value.status == 422


def test_future_timestamp_and_overlong_software_version() -> None:
    value = valid()
    value["captured_at"] = (datetime.now(UTC) + timedelta(minutes=6)).isoformat()
    with pytest.raises(UploadError):
        validate(json.dumps(value).encode())
    value = valid()
    value["packages"]["items"][0]["version"] = "x" * 513
    with pytest.raises(UploadError):
        validate(json.dumps(value).encode())


def test_depth_array_node_and_string_limits() -> None:
    for raw, kwargs in [
        (b"[" * 40 + b"0" + b"]" * 40, {}),
        (json.dumps({"x": [0] * 100001}).encode(), {}),
        (json.dumps(valid()).encode(), {"nodes": 2}),
        (json.dumps({"x": "a" * 65537}).encode(), {}),
    ]:
        with pytest.raises(UploadError):
            validate(raw, **kwargs)


def test_bounded_deterministic_fuzzing() -> None:
    randomizer = random.Random(11)
    for _ in range(100):
        raw = bytes(randomizer.randrange(256) for _ in range(randomizer.randrange(1, 512)))
        with pytest.raises(UploadError):
            validate(raw)


@pytest.mark.parametrize(
    "model,data",
    [
        (
            TokenCreate,
            {
                "server_id": str(uuid4()),
                "certificate_id": str(uuid4()),
                "expires_at": "2027-01-01T00:00:00Z",
                "scope": "admin",
            },
        ),
        (
            CertificateCreate,
            {"certificate_pem": "x", "private_key": "forbidden"},  # pragma: allowlist secret
        ),
    ],
)
def test_credential_allowlists(model: Any, data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(data)


def test_json_escaped_nul_cannot_reach_postgresql_jsonb() -> None:
    value = valid()
    value["collector"]["version"] = "a\x00b"
    with pytest.raises(UploadError) as error:
        validate(json.dumps(value).encode())
    assert error.value.status == 422
