"Published finite request schemas, permission annotations and strong HTTP preconditions."

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "name", ["server-administration", "group-administration", "group-assignment", "manual-ordering"]
)
def test_openapi_contract(name: str) -> None:
    spec = yaml.safe_load((ROOT / "contracts/api" / f"{name}.openapi.yaml").read_text())
    validate(spec)
    assert spec["info"]["version"] == ("0.11.0" if name.startswith("group-") else "0.10.0")
    for path, operations in spec["paths"].items():
        assert path.startswith("/api/v1/dashboard/") and "/inventories" not in path
        for method, op in operations.items():
            assert op["x-permissions"] and "SessionCookie" in op["security"][0]
            if method != "get":
                assert "CsrfToken" in op["security"][0]
                if name.startswith("group-"):
                    assert "requestBody" in op
                    continue
                if not (method == "post" and path.endswith(("/admin/servers", "/admin/groups"))):
                    assert any(p["name"] == "If-Match" and p["required"] for p in op["parameters"])
            for status in (
                [401, 403, 404, 409, 422]
                if name.startswith("group-")
                else [401, 403, 404, 409, 412, 422, 428]
            ):
                assert str(status) in op["responses"]


@pytest.mark.parametrize(
    "name", ["server-metadata", "server-group", "group-assignment", "ordering"]
)
def test_json_schema_rejects_uncontrolled_fields(name: str) -> None:
    schema = json.loads((ROOT / "contracts/inventory" / f"{name}.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert "packages" not in schema["properties"]
