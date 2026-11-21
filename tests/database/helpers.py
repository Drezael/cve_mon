"""Synthetische Identitäten und Inventare für Datenbank-Verhaltenstests."""

import hashlib
import json
import uuid
from typing import Any

import psycopg

Connection = psycopg.Connection[dict[str, Any]]


def server(connection: Connection, **fields: Any) -> uuid.UUID:
    identity = uuid.uuid4().hex
    return uuid.UUID(
        str(
            required_row(
                connection.execute(
                    (
                        "INSERT INTO "
                        "inventory.servers(display_name,inventory_hostname,inventory_name) "
                        "VALUES (%s,%s,%s) RETURNING id"
                    ),
                    (
                        fields.get("display_name", identity),
                        fields.get("hostname", identity),
                        fields.get("inventory_name", "test"),
                    ),
                )
            )["id"]
        )
    )


def group(connection: Connection) -> uuid.UUID:
    return uuid.UUID(
        str(
            required_row(
                connection.execute(
                    (
                        "INSERT INTO inventory.server_groups(name,sort_order) VALUES (%s,%s) "
                        "RETURNING id"
                    ),
                    (uuid.uuid4().hex, uuid.uuid4().int >> 66),
                )
            )["id"]
        )
    )


def user(connection: Connection, username: str | None = None) -> uuid.UUID:
    identity = uuid.uuid4().hex
    return uuid.UUID(
        str(
            required_row(
                connection.execute(
                    (
                        "INSERT INTO security.users(username,email,display_name) VALUES "
                        "(%s,%s,%s) RETURNING id"
                    ),
                    (username or identity, identity + "@example.invalid", identity),
                )
            )["id"]
        )
    )


def snapshot(
    connection: Connection,
    target: uuid.UUID,
    *,
    captured: str = "2026-01-02T10:00:00Z",
    quality: str = "complete",
    inventory_id: uuid.UUID | None = None,
    payload: dict[str, Any] | None = None,
) -> uuid.UUID:
    inventory_id = inventory_id or uuid.uuid4()
    payload = {
        "inventory_id": str(inventory_id),
        "server_id": str(target),
        "schema_version": "1.0",
        "captured_at": captured,
        "collection_status": quality,
        **(payload or {}),
    }
    original = json.dumps(payload).encode()
    return uuid.UUID(
        str(
            required_row(
                connection.execute(
                    (
                        "INSERT INTO "
                        "inventory.snapshots(inventory_id,server_id,schema_version,captured_a"
                        "t,collection_status,content_sha256,original_json,original_bytes) "
                        "VALUES (%s,%s,'1.0',%s,%s,%s,%s,%s) RETURNING id"
                    ),
                    (
                        inventory_id,
                        target,
                        captured,
                        quality,
                        hashlib.sha256(original).digest(),
                        original.decode(),
                        original,
                    ),
                )
            )["id"]
        )
    )


def processed(
    connection: Connection, snapshot_id: uuid.UUID, incomplete: str | None = None
) -> None:
    for section in ("os", "packages", "services", "containers"):
        connection.execute(
            (
                "INSERT INTO "
                "inventory.collection_sections(snapshot_id,section,status) VALUES "
                "(%s,%s,%s)"
            ),
            (snapshot_id, section, "not_collected" if section == incomplete else "complete"),
        )
    connection.execute(
        "UPDATE inventory.snapshots SET processing_status='processed' WHERE id=%s", (snapshot_id,)
    )


def cve(connection: Connection, identifier: str | None = None) -> tuple[str, uuid.UUID]:
    identifier = identifier or "CVE-2026-" + str(uuid.uuid4().int >> 80)
    connection.execute("INSERT INTO cve.records(id,status) VALUES (%s,'published')", (identifier,))
    revision = required_row(
        connection.execute(
            (
                "INSERT INTO "
                "cve.revisions(cve_id,source_id,source_revision,content_sha256,origin"
                "al_json) VALUES (%s,'cve_list','1',sha256('synthetic'::bytea),'{}') "
                "RETURNING id"
            ),
            (identifier,),
        )
    )["id"]
    connection.execute(
        "UPDATE cve.records SET current_revision_id=%s WHERE id=%s", (revision, identifier)
    )
    return (identifier, revision)


def finding(connection: Connection, target: uuid.UUID) -> uuid.UUID:
    inventory = snapshot(connection, target)
    identifier, revision = cve(connection)
    run = required_row(
        connection.execute(
            (
                "INSERT INTO matching.runs(snapshot_id,server_id,rule_version) "
                "VALUES (%s,%s,'test') RETURNING id"
            ),
            (inventory, target),
        )
    )["id"]
    match = required_row(
        connection.execute(
            (
                "INSERT INTO "
                "matching.results(run_id,snapshot_id,server_id,cve_id,cve_revision_id"
                ",component_identity,installed_version,status,rule_id,source_id,evide"
                "nce,reason) VALUES "
                "(%s,%s,%s,%s,%s,'dpkg:openssl:amd64','1:3.0-0ubuntu1','affected','di"
                "stribution','ubuntu','{}','synthetic') RETURNING id"
            ),
            (run, inventory, target, identifier, revision),
        )
    )["id"]
    return uuid.UUID(
        str(
            required_row(
                connection.execute(
                    (
                        "INSERT INTO "
                        "findings.findings(server_id,cve_id,component_identity,risk_level,cur"
                        "rent_match_id) VALUES (%s,%s,'dpkg:openssl:amd64','high',%s) "
                        "RETURNING id"
                    ),
                    (target, identifier, match),
                )
            )["id"]
        )
    )


def required_row(cursor: psycopg.Cursor[dict[str, Any]]) -> dict[str, Any]:
    "Erwartete Zeile explizit absichern, damit fehlende Daten klar fehlschlagen."
    row = cursor.fetchone()
    assert row is not None
    return row
