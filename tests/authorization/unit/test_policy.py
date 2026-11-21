"""Finite roles, default deny, delegation and mass-assignment boundaries."""

from uuid import uuid4

import pytest
from cve_api.authorization.engine import function_decision
from cve_api.authorization.errors import Denied
from cve_api.authorization.permissions import CATALOG, DELEGABLE, SYSTEM_ROLES
from cve_api.authorization.policies import custom_permissions
from cve_api.authorization.principal import Principal
from cve_api.roles.schemas import RoleCreate
from cve_api.users.schemas import UserCreate, UserPatch
from pydantic import ValidationError


def principal(
    role: str = "viewer", *, state: str = "authenticated", mfa: bool = False
) -> Principal:
    return Principal(
        uuid4(), uuid4(), "active", state, mfa, 1, frozenset({role}), SYSTEM_ROLES[role]
    )


def test_catalog_and_exact_system_roles() -> None:
    assert len(CATALOG) == 51
    assert set(SYSTEM_ROLES) == {"admin", "user", "user_admin", "security_analyst", "viewer"}
    assert SYSTEM_ROLES["admin"] == frozenset(CATALOG)
    assert "inventory:upload:dashboard" not in SYSTEM_ROLES["security_analyst"]
    assert "inventory:submit" not in CATALOG
    assert all(right in CATALOG for role in SYSTEM_ROLES.values() for right in role)
    assert all(not CATALOG[c].administrative for c in DELEGABLE)


@pytest.mark.parametrize(
    "action",
    [
        "unknown",
        "*",
        "users:manage",
        "inventory:submit",
        "role:create",
        "group:assign",
        "server:reorder",
    ],
)
def test_viewer_default_denies_privileged_and_unknown(action: str) -> None:
    assert not function_decision(principal(), action).allow


@pytest.mark.parametrize("role", ["admin", "user_admin", "security_analyst", "viewer"])
def test_all_role_permissions_are_explicit(role: str) -> None:
    for action in CATALOG:
        assert function_decision(principal(role, mfa=True), action).allow == (
            action in SYSTEM_ROLES[role]
        )


@pytest.mark.parametrize(
    "state",
    [
        "unauthenticated",
        "password_verified",
        "mfa_pending",
        "mfa_setup_required",
        "mfa_recovery",
        "expired",
        "revoked",
    ],
)
def test_incomplete_identity_has_no_management_rights(state: str) -> None:
    assert not function_decision(principal("admin", state=state, mfa=True), "user:create").allow


def test_admin_can_choose_password_only_authentication() -> None:
    assert function_decision(principal("admin"), "user:list").allow


@pytest.mark.parametrize(
    "right",
    [
        "*",
        "role:assign:privileged",
        "group:assign",
        "group:primary:assign",
        "group:reorder",
        "server:reorder",
        "user:create",
        "inventory:submit",
        "unknown",
    ],
)
def test_custom_role_cannot_receive_protected_rights(right: str) -> None:
    with pytest.raises(Denied):
        custom_permissions([right])


@pytest.mark.parametrize(
    "property",
    [
        "roles",
        "role_ids",
        "is_admin",
        "mfa_secret",
        "password_hash",
        "status",
        "id",
        "auth_version",
        "primary_group_id",
    ],
)
def test_user_patch_has_no_mass_assignment(property: str) -> None:
    with pytest.raises(ValidationError):
        UserPatch.model_validate(
            {"version": 1, "reason": "test", "display_name": "valid", property: "forged"}
        )


@pytest.mark.parametrize("extra", ["roles", "password", "status", "is_admin"])
def test_creation_has_no_initial_secret_or_privilege(extra: str) -> None:
    with pytest.raises(ValidationError):
        UserCreate.model_validate(
            {
                "username": "test",
                "email": "test@example.test",
                "display_name": "Test",
                extra: "forged",
            }
        )


def test_valid_nonprivileged_custom_role() -> None:
    body = RoleCreate(
        code="upload_reader",
        name="Upload Reader",
        permissions=["server:read", "inventory:upload:dashboard"],
    )
    custom_permissions(body.permissions)


def test_standard_user_has_no_instance_administration_permissions() -> None:
    assert SYSTEM_ROLES["user"] <= SYSTEM_ROLES["admin"]
    assert all(not CATALOG[permission].administrative for permission in SYSTEM_ROLES["user"])
    assert "server:inventory:manage" in SYSTEM_ROLES["user"]
    assert "finding:read" in SYSTEM_ROLES["user"]
    assert "instance:settings:manage" not in SYSTEM_ROLES["user"]
