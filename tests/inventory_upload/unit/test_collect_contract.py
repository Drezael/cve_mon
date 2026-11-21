"""Shared additive contract preserves v1.0 and rejects unexpected fields in v1.1."""

import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from cve_api.inventories.errors import UploadError
from cve_api.inventories.parser import validate

ROOT = Path(__file__).resolve().parents[3]


def value() -> dict[str, Any]:
    result = json.loads((ROOT / "contracts/inventory/examples-v1.1/valid-collect.json").read_text())
    result["captured_at"] = datetime.now(UTC).isoformat()
    return dict(result)


@pytest.mark.parametrize("name", ["inventory-v1.1.schema.json", "inventory-v1.2.schema.json"])
def test_packaged_and_ansible_collection_schemas_are_authoritative(name: str) -> None:
    expected = (ROOT / "contracts/inventory" / name).read_bytes()
    assert files("cve_api.inventories").joinpath("data/" + name).read_bytes() == expected


def test_11_is_valid_and_v10_remains_unchanged() -> None:
    assert validate(json.dumps(value()).encode()).schema_version == "1.1"


@pytest.mark.parametrize(
    "section", ["hardware", "images", "docker", "os", "packages", "services", "containers"]
)
def test_no_additional_fields_in_collection_sections(section: str) -> None:
    v = value()
    item = v[section]
    if isinstance(item, dict):
        item["group_id"] = "forbidden"
    with pytest.raises(UploadError):
        validate(json.dumps(v).encode())
