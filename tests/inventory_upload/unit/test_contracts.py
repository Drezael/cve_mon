"Versioned upload contracts explicitly preserve Inventory v1 and truthful accepted receipts."

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "name",
    [
        "inventory-technical-upload",
        "inventory-dashboard-upload",
        "inventory-submission-status",
        "inventory-credentials",
    ],
)
def test_upload_openapi_contracts(name: str) -> None:
    spec = yaml.safe_load((ROOT / "contracts/api" / f"{name}.openapi.yaml").read_text())
    validate(spec)
    assert spec["info"]["version"] == "0.11.0"
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            assert op["x-permission"]
            if path.startswith("/api/v1/inventories"):
                assert {"MutualTLS", "UploadToken"} == set(op["security"][0])
            else:
                assert "SessionCookie" in op["security"][0]
                if method != "get":
                    assert "CsrfToken" in op["security"][0]
            for status in ["401", "403", "404", "409", "413", "415", "422", "429", "503"]:
                assert status in op["responses"]


def test_receipt_never_claims_processing_or_exposes_raw_inventory() -> None:
    value = json.loads((ROOT / "contracts/inventory/submission-response.schema.json").read_text())
    Draft202012Validator.check_schema(value)
    assert value["additionalProperties"] is False
    assert value["properties"]["status"]["const"] == "accepted"
    assert not {"payload", "token", "job_id", "snapshot_id"} & set(value["properties"])
