"""Prüfe Phase-0-Verträge und tatsächliche Fehlererkennung in Phase 1."""

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from scripts.validate_contracts import (
    MANIFEST,
    load_json,
    local_references,
    security_invariants,
    validate_contracts,
    validate_document_links,
    validate_examples,
    validate_openapi,
    validate_policy,
)
from scripts.validate_repository import validate_configuration


@pytest.fixture
def inventory_validator(repository_root: Path) -> Draft202012Validator:
    schema = load_json(repository_root / "contracts/inventory/inventory-v1.schema.json")
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def inventory(repository_root: Path) -> dict[str, Any]:
    value = load_json(repository_root / "contracts/inventory/examples/valid-ubuntu.json")
    assert isinstance(value, dict)
    return value


def test_phase_zero_contracts(repository_root: Path) -> None:
    assert validate_contracts(repository_root) == []


def test_example_expectations(repository_root: Path) -> None:
    manifest = load_json(repository_root / MANIFEST)
    assert len(manifest["examples"]) == 6
    assert validate_examples(repository_root, manifest) == []


@pytest.mark.parametrize(
    "field",
    [
        "group_id",
        "group_ids",
        "primary_group_id",
        "group_sort_order",
        "display_order",
    ],
)
@pytest.mark.parametrize(
    "location", ["root", "os", "package", "collector", "source_package", "service", "container"]
)
def test_administrative_fields_are_rejected_everywhere(
    inventory_validator: Draft202012Validator,
    inventory: dict[str, Any],
    field: str,
    location: str,
) -> None:
    inventory["services"]["items"] = [{"name": "demo", "state": "running"}]
    inventory["containers"] = {
        "status": "complete",
        "items": [
            {
                "container_id": "synthetic",
                "image_reference": "example.invalid/demo:1",
                "state": "running",
                "collection_status": "complete",
            }
        ],
    }
    target = {
        "root": inventory,
        "os": inventory["os"]["data"],
        "package": inventory["packages"]["items"][0],
        "collector": inventory["collector"],
        "source_package": inventory["packages"]["items"][0]["source_package"],
        "service": inventory["services"]["items"][0],
        "container": inventory["containers"]["items"][0],
    }[location]
    target[field] = "untrusted"
    assert not inventory_validator.is_valid(inventory)


@pytest.mark.parametrize(
    "field,value",
    [
        ("server_id", "hostname"),
        ("inventory_id", "not-a-uuid"),
        ("captured_at", "2026-11-05T18:00:00"),
        ("captured_at", "2026-02-30T18:00:00Z"),
        ("schema_version", "2.0"),
    ],
)
def test_identity_and_timestamp_formats_are_enforced(
    inventory_validator: Draft202012Validator,
    inventory: dict[str, Any],
    field: str,
    value: str,
) -> None:
    inventory[field] = value
    assert not inventory_validator.is_valid(inventory)


def test_empty_partial_failed_and_missing_sections_are_distinct(
    inventory_validator: Draft202012Validator,
    inventory: dict[str, Any],
) -> None:
    inventory["packages"]["items"] = []
    assert inventory_validator.is_valid(inventory)
    inventory["packages"] = {"status": "failed"}
    assert not inventory_validator.is_valid(inventory)  # Gesamt-complete wäre falsch.
    inventory["collection_status"] = "partial"
    assert inventory_validator.is_valid(inventory)
    inventory["packages"]["items"] = []
    assert not inventory_validator.is_valid(inventory)  # Fehlschlag ist keine leere Liste.
    inventory.pop("packages")
    assert inventory_validator.is_valid(inventory)
    inventory["collection_status"] = "failed"
    assert not inventory_validator.is_valid(inventory)  # OS ist weiterhin ein positiver Nachweis.
    inventory["os"] = {"status": "failed"}
    inventory.pop("services")
    assert inventory_validator.is_valid(inventory)


def test_versions_are_preserved(inventory: dict[str, Any]) -> None:
    versions = [item["version"] for item in inventory["packages"]["items"]]
    assert "3.0.13-0ubuntu3.6" in versions
    assert "1:2.0.0-0ubuntu1~24.04.2" in versions


@pytest.mark.parametrize("contents", ['{"id":1,"id":2}', '{"value":NaN}', '{"value":Infinity}'])
def test_ambiguous_json_is_rejected(tmp_path: Path, contents: str) -> None:
    path = tmp_path / "ambiguous.json"
    path.write_text(contents)
    assert validate_configuration(path)


def test_negative_example_must_fail_for_declared_reason(repository_root: Path) -> None:
    manifest = load_json(repository_root / MANIFEST)
    manifest["examples"][-1]["error_pointer"] = "/unrelated"
    assert any("Ablehnungsgrund" in error for error in validate_examples(repository_root, manifest))


def test_unknown_examples_require_explicit_expectation(
    repository_root: Path, tmp_path: Path
) -> None:
    target = tmp_path / "contracts/inventory"
    shutil.copytree(repository_root / "contracts/inventory", target)
    (target / "examples/new.json").write_text("{}")
    manifest = load_json(repository_root / MANIFEST)
    assert any("Manifest" in error for error in validate_examples(tmp_path, manifest))


@pytest.mark.parametrize(
    "mutation", ["auth-or", "admin-token", "schema-copy", "status-target", "status-auth", "scope"]
)
def test_openapi_security_invariant_changes_are_rejected(
    repository_root: Path,
    mutation: str,
) -> None:
    spec = yaml.safe_load((repository_root / "contracts/api/openapi.yaml").read_text())
    if mutation == "auth-or":
        spec["paths"]["/api/v1/inventories"]["post"]["security"] = [
            {"MutualTLS": []},
            {"UploadToken": []},
        ]
    elif mutation == "admin-token":
        spec["paths"]["/api/v1/dashboard/admin/servers"]["post"]["security"] = [
            {"UploadToken": []},
        ]
    elif mutation == "schema-copy":
        spec["components"]["schemas"]["Inventory"] = {"type": "object"}
    elif mutation == "status-auth":
        spec["paths"]["/api/v1/dashboard/deployment/status"]["get"]["security"] = []
    elif mutation == "scope":
        spec["paths"]["/api/v1/inventories"]["post"]["x-permission"] = "groups:manage"
    else:
        spec["paths"]["/api/v1/dashboard/deployment/status"]["get"]["parameters"] = [
            {"name": "target", "in": "query", "schema": {"type": "string"}},
        ]
    assert security_invariants(spec)


def test_openapi_semantic_errors_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "openapi.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "openapi": "3.1.0",
                "info": {"title": "test", "version": "1"},
                "paths": {"/test": {"get": {"responses": {"200": {}}}}},
            }
        )
    )
    assert validate_openapi(path, tmp_path)  # Response.description fehlt.


@pytest.mark.parametrize("reference", ["https://invalid.test/schema.json", "../../outside.json"])
def test_remote_and_escaping_refs_are_rejected(tmp_path: Path, reference: str) -> None:
    path = tmp_path / "openapi.yaml"
    path.write_text(yaml.safe_dump({"$ref": reference}))
    assert local_references(path, tmp_path)


def test_broken_local_ref_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "openapi.yaml"
    path.write_text(yaml.safe_dump({"$ref": "missing.json"}))
    assert local_references(path, tmp_path)


@pytest.mark.parametrize(
    "mutation",
    ["groups", "egress", "dashboard-db", "public-port", "internal-net", "inventory-role"],
)
def test_architecture_policy_regressions_are_rejected(
    repository_root: Path,
    tmp_path: Path,
    mutation: str,
) -> None:
    policy = copy.deepcopy(load_json(repository_root / "contracts/security/service-access-v1.json"))
    if mutation == "groups":
        policy["group_write_roles"].append("inventory_processor")
    elif mutation == "egress":
        policy["services"]["cve-matcher"]["networks"].append("cve_egress_external")
    elif mutation == "dashboard-db":
        policy["services"]["cve-dashboard"]["database_roles"].append("dashboard_admin")
    elif mutation == "internal-net":
        policy["networks"]["cve_internal"]["internal"] = False
    elif mutation == "inventory-role":
        policy["services"]["cve-inventory"]["database_roles"].append("dashboard_admin")
    else:
        policy["public_ports"]["cve-postgres"] = [5432]
    path = tmp_path / "contracts/security/service-access-v1.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(policy))
    assert validate_policy(tmp_path)


def test_broken_document_links_fail(git_repository: Path) -> None:
    (git_repository / "README.md").write_text("[broken](missing.md)\n")
    assert validate_document_links(git_repository)
    (git_repository / "missing.md").write_text("# Found\n")
    assert validate_document_links(git_repository) == []
