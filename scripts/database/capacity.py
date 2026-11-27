"""Read-only database growth estimates and legacy mailbox audit, without mailbox contents."""

import argparse
import json
import re
from collections import Counter
from typing import Any

import psycopg
from cve_common.email_address import normalize_address

from scripts.database.manage import connect
from scripts.infrastructure.manage import load_config


def collect(connection: psycopg.Connection[dict[str, Any]]) -> dict[str, Any]:
    connection.execute("SET TRANSACTION READ ONLY")
    connection.execute("SET LOCAL statement_timeout='5s'")
    tables = connection.execute("""
SELECT n.nspname AS schema,c.relname AS table,greatest(c.reltuples,0)::bigint AS estimated_rows,
 pg_total_relation_size(c.oid) AS total_bytes,pg_indexes_size(c.oid) AS index_bytes
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE c.relkind IN ('r','m') AND n.nspname IN
 ('inventory','matching','findings','automation','security','status','cve')
ORDER BY pg_total_relation_size(c.oid) DESC,n.nspname,c.relname
""").fetchall()
    totals = connection.execute("""
SELECT (SELECT count(*) FROM inventory.servers) AS servers,
 (SELECT count(*) FROM inventory.snapshots) AS snapshots,
 pg_database_size(current_database()) AS database_bytes
""").fetchone()
    assert totals is not None
    invalid: list[str] = []
    noncanonical = 0
    users = connection.execute(
        "SELECT id,email FROM security.users ORDER BY id LIMIT 100001"
    ).fetchall()
    for user in users[:100000]:
        try:
            canonical = normalize_address(user["email"] or "")
            noncanonical += canonical != user["email"]
        except ValueError:
            if len(invalid) < 1000:
                invalid.append(str(user["id"]))
    retained = sum(t["total_bytes"] for t in tables if t["schema"] in {"inventory", "matching"})
    sample = connection.execute(
        "SELECT decision FROM matching.component_results "
        "ORDER BY result_id DESC,position LIMIT 10001"
    ).fetchall()
    gaps: Counter[str] = Counter()
    for item in sample[:10000]:
        decision = item["decision"]
        reason = decision.get("reason", "unknown")
        if decision.get("status") in {"unknown", "potentially_affected"}:
            gaps[reason if re.fullmatch(r"[a-z_]{1,80}", str(reason)) else "unknown"] += 1
    return {
        "counts": totals,
        "tables": tables,
        "estimated_inventory_matching_bytes_per_snapshot": retained / totals["snapshots"]
        if totals["snapshots"]
        else None,
        "mailbox_audit": {
            "checked": min(len(users), 100000),
            "capped": len(users) > 100000,
            "invalid_user_ids": invalid,
            "noncanonical_valid": noncanonical,
        },
        "matching_gaps": {
            "sampled": min(len(sample), 10000),
            "capped": len(sample) > 10000,
            "reasons": dict(gaps.most_common()),
        },
        "note": "Includes retained history and indexes; estimates require ANALYZE. Read-only.",
    }


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    with connect(load_config()) as connection:
        print(json.dumps(collect(connection), indent=2))


if __name__ == "__main__":
    main()
