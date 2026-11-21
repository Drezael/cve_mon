"""Finite human permission catalog; legacy/machine permissions cannot leak into browser roles."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Permission:
    code: str
    description: str
    administrative: bool = False
    object_scope: str | None = None
    reauthentication: bool = False
    delegable: bool = False


USER_ACTIONS = (
    "list",
    "read",
    "create",
    "update",
    "enable",
    "disable",
    "archive",
    "session:revoke",
    "role:assign",
    "mfa:recovery",
)
ROLE_ACTIONS = ("list", "create", "update", "delete", "assign:privileged")
SERVER_ACTIONS = ("read", "create", "update", "delete", "restore", "acl:manage", "reorder")
GROUP_ACTIONS = ("read",)
CATALOG: dict[str, Permission] = {}
for namespace, actions in (
    ("user", USER_ACTIONS),
    ("role", ROLE_ACTIONS),
    ("server", SERVER_ACTIONS),
    ("group", GROUP_ACTIONS),
):
    for action in actions:
        name = namespace + ":" + action
        administrative = not (namespace in {"server", "group"} and action == "read")
        CATALOG[name] = Permission(
            name,
            name.replace(":", " "),
            administrative,
            "view" if namespace in {"server", "group"} and action == "read" else None,
            administrative and action not in {"list", "read"},
            not administrative,
        )
for name, scope in (
    ("inventory:read", "view"),
    ("inventory:upload:dashboard", "inventory_upload"),
    ("security:overview:read", "view"),
    ("cve:read", "view"),
    ("finding:read", "findings_read"),
    ("finding:update", "findings_manage"),
    ("deployment:status:read", None),
):
    CATALOG[name] = Permission(name, name.replace(":", " "), False, scope, False, True)
CATALOG["permission:read"] = Permission("permission:read", "Read permission catalog", True)
CATALOG["audit:read"] = Permission("audit:read", "Read authorized audit metadata", True)
for name in [
    "finding:close",
    "finding:review:confirm",
    "finding:exception:approve",
    "finding:policy:manage",
]:
    CATALOG[name] = Permission(
        name,
        name.replace(":", " "),
        True,
        None if name == "finding:policy:manage" else "findings_manage",
        True,
        False,
    )
for name in [
    "read",
    "preferences:update",
    "rule:read",
    "rule:manage",
    "template:read",
    "template:manage",
    "delivery:read",
    "workflow:read",
]:
    code = "notification:" + name
    CATALOG[code] = Permission(
        code,
        code.replace(":", " "),
        name not in {"read", "preferences:update"},
        None,
        name in {"rule:manage", "template:manage"},
        False,
    )
for name, step_up in [
    ("deployment:diagnostics:read", False),
    ("deployment:maintenance:manage", True),
    ("deployment:service:restart", False),
    ("notification:smtp:manage", False),
]:
    CATALOG[name] = Permission(name, name.replace(":", " "), True, None, step_up, False)
CATALOG["instance:settings:manage"] = Permission(
    "instance:settings:manage", "Manage instance settings", True
)
CATALOG["cve:update"] = Permission("cve:update", "Request CVE data update", True)
CATALOG["server:inventory:manage"] = Permission(
    "server:inventory:manage", "Server hinzufügen und aktualisieren", False, None, False, True
)
SYSTEM_ROLES = {
    "user": frozenset(
        {
            "server:inventory:manage",
            "server:read",
            "group:read",
            "inventory:read",
            "cve:read",
            "finding:read",
            "finding:update",
            "notification:read",
            "notification:preferences:update",
            "security:overview:read",
        }
    ),
    "admin": frozenset(CATALOG),
    "user_admin": frozenset(
        {
            "notification:read",
            "notification:preferences:update",
            "user:list",
            "user:read",
            "user:create",
            "user:update",
            "user:enable",
            "user:disable",
            "user:session:revoke",
            "user:role:assign",
            "role:list",
            "permission:read",
            "audit:read",
        }
    ),
    "security_analyst": frozenset(
        {
            "server:read",
            "group:read",
            "inventory:read",
            "cve:read",
            "finding:read",
            "notification:read",
            "notification:preferences:update",
            "security:overview:read",
            "deployment:status:read",
        }
    ),
    "viewer": frozenset(
        {
            "server:read",
            "group:read",
            "inventory:read",
            "cve:read",
            "finding:read",
            "notification:read",
            "notification:preferences:update",
        }
    ),
}
DELEGABLE = frozenset(code for code, spec in CATALOG.items() if spec.delegable)
ACL_RIGHTS = frozenset({"view", "inventory_upload", "findings_read", "findings_manage"})
ACL_COLUMNS = {
    "view": "can_read",
    "inventory_upload": "can_upload",
    "findings_read": "findings_read",
    "findings_manage": "findings_manage",
}
