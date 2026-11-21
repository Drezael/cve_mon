"""Validate the published permission matrix and three administration API contracts."""

from pathlib import Path

import yaml
from cve_api.authorization.permissions import CATALOG, SYSTEM_ROLES
from openapi_spec_validator import validate


def test_published_catalog_and_matrix_match_runtime_exactly() -> None:
    root = Path(__file__).resolve().parents[3]
    catalog = yaml.safe_load((root / "contracts/security/permission-catalog.yaml").read_text())
    matrix = yaml.safe_load((root / "contracts/security/role-matrix.yaml").read_text())
    rows = catalog["permissions"]
    assert len({r["code"] for r in rows}) == len(rows)
    assert {r["code"] for r in rows if r["identity_type"] == "human"} == set(CATALOG)
    for role, values in SYSTEM_ROLES.items():
        assert set(matrix["system_roles"][role]["permissions"]) == values
    assert not matrix["policy"]["implicit_group_inheritance"]


def test_administration_contracts_are_valid_and_protect_mutations() -> None:
    root = Path(__file__).resolve().parents[3]
    for filename in (
        "user-administration.openapi.yaml",
        "role-administration.openapi.yaml",
        "server-access.openapi.yaml",
    ):
        spec = yaml.safe_load((root / "contracts/api" / filename).read_text())
        validate(spec)
        assert spec["info"]["version"] == "0.9.0"
        for path, methods in spec["paths"].items():
            assert "inventories/upload" not in path
            for method, operation in methods.items():
                if method != "get":
                    assert any("CsrfToken" in item for item in operation["security"])
