"""Bounded authorization inspection and explicit private out-of-band handoff issuance."""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from uuid import UUID

from cve_api.auth.service import AuthService
from cve_api.authorization.permissions import SYSTEM_ROLES
from cve_api.users.activation import Handoff

from scripts.database import manage as db
from scripts.infrastructure.manage import load_config
from scripts.security.manage import private_write, settings


async def issue(config: object, user: UUID, request: UUID | None, path: Path) -> None:
    from scripts.infrastructure.manage import Config

    assert isinstance(config, Config)
    if path.exists() or path.is_symlink():
        raise ValueError("New private output file required")
    auth = AuthService(settings(config))
    await auth.open()
    try:
        token = await Handoff(auth).issue(user, request)
        private_write(path, token)
    finally:
        await auth.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["check", "roles", "acls", "last-admin", "issue-activation", "issue-recovery"],
    )
    parser.add_argument("--server-id", type=UUID)
    parser.add_argument("--user-id", type=UUID)
    parser.add_argument("--request-id", type=UUID)
    parser.add_argument("--output-file", type=Path)
    args = parser.parse_args()
    try:
        config = load_config()
        if args.action.startswith("issue-"):
            if (
                args.user_id is None
                or args.output_file is None
                or (args.action == "issue-recovery" and args.request_id is None)
            ):
                raise ValueError("Explicit target and private output required")
            asyncio.run(issue(config, args.user_id, args.request_id, args.output_file))
            print(json.dumps({"result": "ok", "private_handoff_written": True}))
            return 0
        with db.connect(config, "api_security") as c:
            if args.action == "last-admin":
                row = c.execute("SELECT security.authorization_status() AS status").fetchone()
                assert row is not None
                status = row["status"]
                if status["invariant_armed"] and status["usable_administrators"] == 0:
                    raise ValueError("No usable administrator")
                print(json.dumps(status))
            elif args.action == "acls":
                if args.server_id is None:
                    raise ValueError("Server UUID required")
                rows = c.execute(
                    (
                        "SELECT user_id,server_id,can_read,can_upload,findings_r"
                        "ead,findings_manage,version FROM security.user_server_a"
                        "ccess WHERE server_id=%s ORDER BY user_id LIMIT 100"
                    ),
                    (args.server_id,),
                ).fetchall()
                print(json.dumps(rows, default=str))
            else:
                rows = c.execute(
                    "SELECT r.code,p.permission_code FROM security.roles r L"
                    "EFT JOIN security.role_permissions p ON p.role_id=r.id "
                    "WHERE r.is_system ORDER BY r.code,p.permission_code"
                ).fetchall()
                actual: dict[str, set[str]] = {code: set() for code in SYSTEM_ROLES}
                for row in rows:
                    if row["permission_code"]:
                        actual.setdefault(row["code"], set()).add(row["permission_code"])
                if {k: frozenset(v) for k, v in actual.items()} != SYSTEM_ROLES:
                    raise ValueError("System role seed mismatch")
                print(json.dumps({k: sorted(v) for k, v in actual.items()}))
        print(json.dumps({"result": "ok", "action": args.action}))
        return 0
    except Exception as error:
        print(json.dumps({"result": "error", "code": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
