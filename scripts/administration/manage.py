"Read-only administrative consistency, isolation and operational aggregate diagnostics."

import argparse
import json
import subprocess

import psycopg

from scripts.database.manage import connect
from scripts.infrastructure.manage import load_config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "check", choices=["all", "schema", "groups", "primary", "ordering", "permissions"]
    )
    args = parser.parse_args()
    try:
        config = load_config()
        result: dict[str, object] = {}
        with connect(config) as c:
            c.execute("SET TRANSACTION READ ONLY")
            if args.check in {"all", "schema"}:
                row = c.execute(
                    "SELECT count(*) AS n FROM information_schema.columns WH"
                    "ERE table_"
                    "schema='inventory' AND table_name='servers' AND column_"
                    "name IN ('"
                    "exposure','display_order','created_by','updated_by','version')"
                ).fetchone()
                assert row is not None and row["n"] == 5, "Missing administrative columns"
                result["revision"] = c.execute(
                    "SELECT version_num FROM public.alembic_version"
                ).fetchone()
            if args.check in {"all", "groups", "primary"}:
                row = c.execute(
                    "SELECT count(*) AS n FROM inventory.servers WHERE primary_group_id IS NOT NULL"
                ).fetchone()
                assert row is not None and row["n"] == 0, "Retired primary group must remain empty"
                row = c.execute(
                    "SELECT count(*) AS n FROM inventory.server_groups g "
                    "LEFT JOIN security.users u ON u.id=g.owner_id WHERE u.id IS NULL"
                ).fetchone()
                assert row is not None and row["n"] == 0, "Missing personal group owner"
                result["personal_groups"] = "consistent"
            if args.check in {"all", "ordering"}:
                for table, key, col in [
                    ("inventory.servers", "", "display_order"),
                ]:
                    row = c.execute(
                        "SELECT count(*) AS n FROM (SELECT "
                        + key
                        + col
                        + " FROM "
                        + table
                        + " GROUP BY "
                        + key
                        + col
                        + " HAVING count(*)>1 OR "
                        + col
                        + " IS NULL OR "
                        + col
                        + "<0) invalid"
                    ).fetchone()
                    assert row is not None and row["n"] == 0, "Invalid order context"
                result["ordering"] = "consistent"
            if args.check in {"all", "permissions"}:
                for role in [
                    "api_ingest",
                    "inventory_processor",
                    "matcher",
                    "importer",
                    "enricher",
                    "event_dispatcher",
                    "api_security",
                ]:
                    for table, column in [
                        ("inventory.servers", "primary_group_id"),
                        ("inventory.servers", "display_order"),
                        ("inventory.servers", "criticality"),
                        ("inventory.server_groups", "sort_order"),
                    ]:
                        if role == "api_security" and table == "inventory.server_groups":
                            continue  # Trusted account API owns personal group commands.
                        row = c.execute(
                            "SELECT has_column_privilege(%s,%s,%s,'UPDATE') AS allowed",
                            (role, table, column),
                        ).fetchone()
                        assert row is not None and not row["allowed"], (
                            "Technical role has administrative writes"
                        )
                row = c.execute(
                    "SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolb"
                    "ypassrls A"
                    "S elevated FROM pg_roles WHERE rolname='dashboard_admin'"
                ).fetchone()
                assert row is not None and not row["elevated"], "Elevated administration role"
                for table in ["security.password_credentials", "security.mfa_methods"]:
                    row = c.execute(
                        "SELECT has_table_privilege('dashboard_admin',%s,'SELECT') AS allowed",
                        (table,),
                    ).fetchone()
                    assert row is not None and not row["allowed"], "Sensitive full-table access"
                result["permissions"] = "isolated"
            result["counts"] = c.execute(
                "SELECT (SELECT count(*) FROM inventory.servers) AS regi"
                "stered_ser"
                "vers,(SELECT count(*) FROM inventory.servers WHERE stat"
                "us='active"
                "') AS active_servers,(SELECT count(*) FROM inventory.se"
                "rvers WHER"
                "E status='archived') AS archived_servers,(SELECT count("
                "*) FROM in"
                "ventory.server_groups WHERE status='active') AS active_"
                "groups,(SE"
                "LECT count(*) FROM inventory.server_group_memberships) "
                "AS members"
                "hips,(SELECT count(*) FROM security.audit_log WHERE act"
                "ion='admin"
                "istration.denied') AS failed_operations,(SELECT count(*"
                ") FROM sec"
                "urity.audit_log WHERE action='administration.denied' AN"
                "D metadata"
                "->>'status'='412') AS version_conflicts"
            ).fetchone()
        print(json.dumps({"result": "ok", "check": args.check, **result}, default=str))
        return 0
    except (
        OSError,
        ValueError,
        AssertionError,
        subprocess.SubprocessError,
        psycopg.Error,
    ) as error:
        print(json.dumps({"result": "error", "code": type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
