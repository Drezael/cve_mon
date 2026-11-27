"Fachliche Constraints, Historie, unveränderte Originaldaten und isolierte Sortierung."

import uuid

import psycopg
import pytest

from tests.database.helpers import (
    Connection,
    cve,
    finding,
    group,
    processed,
    required_row,
    server,
    snapshot,
    user,
)

pytestmark = pytest.mark.database


def test_personal_memberships_are_multiple_and_legacy_primary_is_rejected(
    owner: Connection,
) -> None:
    target = server(owner)
    one, two = group(owner), group(owner)
    owner.execute(
        "INSERT INTO inventory.server_group_memberships(server_id,group_id) VALUES (%s,%s),(%s,%s)",
        (target, one, target, two),
    )
    owner.execute("SET CONSTRAINTS ALL IMMEDIATE")
    assert owner.execute(
        "SELECT count(*) n FROM inventory.server_group_memberships WHERE server_id=%s", (target,)
    ).fetchone() == {"n": 2}
    with pytest.raises(psycopg.errors.CheckViolation, match="primary_group_retired"):
        owner.execute(
            "UPDATE inventory.servers SET primary_group_id=%s,version=version+1 WHERE id=%s",
            (two, target),
        )


def test_personal_membership_removal_and_server_stale_version(owner: Connection) -> None:
    target = server(owner)
    grouping = group(owner)
    owner.execute(
        ("INSERT INTO inventory.server_group_memberships(server_id,group_id) VALUES (%s,%s)"),
        (target, grouping),
    )
    owner.execute(
        "UPDATE inventory.servers SET description='changed',version=2 WHERE id=%s", (target,)
    )
    owner.execute("DELETE FROM inventory.server_group_memberships WHERE server_id=%s", (target,))
    owner.execute(
        "UPDATE inventory.servers SET description='again',version=3 WHERE id=%s", (target,)
    )
    owner.execute("SET CONSTRAINTS ALL IMMEDIATE")
    with pytest.raises(psycopg.errors.SerializationFailure):
        owner.execute("UPDATE inventory.servers SET display_name='stale' WHERE id=%s", (target,))


def test_sort_order_single_truth_and_deferred_swap(owner: Connection) -> None:
    target = server(owner)
    one, two = (group(owner), group(owner))
    owner.execute(
        (
            "INSERT INTO "
            "inventory.server_group_memberships(server_id,group_id,display_order)"
            " VALUES (%s,%s,3),(%s,%s,9)"
        ),
        (target, one, target, two),
    )
    assert [
        row["position"]
        for row in owner.execute(
            ("SELECT position FROM dashboard.server_order WHERE server_id=%s ORDER BY position"),
            (target,),
        )
    ] == [3, 9]
    first = required_row(
        owner.execute("SELECT sort_order FROM inventory.server_groups WHERE id=%s", (one,))
    )["sort_order"]
    second = required_row(
        owner.execute("SELECT sort_order FROM inventory.server_groups WHERE id=%s", (two,))
    )["sort_order"]
    owner.execute(
        ("UPDATE inventory.server_groups SET sort_order=%s,version=version+1 WHERE id=%s"),
        (second, one),
    )
    owner.execute(
        ("UPDATE inventory.server_groups SET sort_order=%s,version=version+1 WHERE id=%s"),
        (first, two),
    )
    owner.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.parametrize(
    "query",
    [
        (
            "INSERT INTO "
            "inventory.servers(display_name,inventory_hostname,inventory_name,sta"
            "tus) VALUES ('a','b','c','unexpected')"
        ),
        (
            "INSERT INTO "
            "inventory.servers(display_name,inventory_hostname,inventory_name) "
            "VALUES ('','b','c')"
        ),
        "INSERT INTO inventory.server_groups(name,sort_order) VALUES ('invalid',-1)",
        (
            "INSERT INTO inventory.server_group_memberships(server_id,group_id) "
            "VALUES (gen_random_uuid(),gen_random_uuid())"
        ),
        "INSERT INTO cve.records(id,status) VALUES ('INVALID','published')",
        (
            "INSERT INTO security.users(username,email,display_name,status) "
            "VALUES ('a','a@example.invalid','a','unexpected')"
        ),
    ],
)
def test_invalid_values(owner: Connection, query: str) -> None:
    with pytest.raises(psycopg.IntegrityError):
        owner.execute(query)


def test_normalized_server_identity(owner: Connection) -> None:
    server(owner, hostname="host-A", inventory_name="production")
    with pytest.raises(psycopg.errors.UniqueViolation):
        server(owner, hostname="HOST-a", inventory_name="PRODUCTION")


def test_original_identity_immutable(owner: Connection) -> None:
    target = server(owner)
    with pytest.raises(psycopg.Error):
        owner.execute(
            "UPDATE inventory.servers SET id=gen_random_uuid(),version=2 WHERE id=%s", (target,)
        )


def test_snapshot_history_partial_and_late(owner: Connection) -> None:
    target = server(owner)
    newest = snapshot(owner, target, captured="2026-02-01T00:00:00Z")
    processed(owner, newest)
    partial = snapshot(owner, target, captured="2026-03-01T00:00:00Z", quality="partial")
    processed(owner, partial, "packages")
    late = snapshot(owner, target, captured="2026-01-01T00:00:00Z")
    processed(owner, late)
    assert (
        required_row(
            owner.execute(
                "SELECT id FROM inventory.current_snapshots WHERE server_id=%s", (target,)
            )
        )["id"]
        == newest
    )
    sections = {
        r["section"]: r["snapshot_id"]
        for r in owner.execute(
            "SELECT * FROM inventory.effective_sections WHERE server_id=%s", (target,)
        )
    }
    assert sections["packages"] == newest and sections["containers"] == partial
    owner.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_complete_requires_collection_quality(owner: Connection) -> None:
    target = server(owner)
    snap = snapshot(owner, target)
    owner.execute(
        "UPDATE inventory.snapshots SET processing_status='processed' WHERE id=%s", (snap,)
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        owner.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.parametrize("status", ["inactive", "archived"])
def test_no_snapshot_for_inactive_server(owner: Connection, status: str) -> None:
    target = server(owner)
    owner.execute(
        (
            "UPDATE inventory.servers SET status=%s,archived_at=CASE WHEN "
            "%s='archived' THEN now() END,version=2 WHERE id=%s"
        ),
        (status, status, target),
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        snapshot(owner, target)


@pytest.mark.parametrize(
    "payload",
    [{"groups": ["x"]}, {"nested": {"primary_group_id": "x"}}, {"os": [{"display_order": 2}]}],
)
def test_no_administrative_fields_in_inventory(
    owner: Connection, payload: dict[str, object]
) -> None:
    target = server(owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        snapshot(owner, target, payload=payload)


def test_duplicate_inventory_and_hash_immutability(owner: Connection) -> None:
    target = server(owner)
    identity = uuid.uuid4()
    snapshot(owner, target, inventory_id=identity)
    with pytest.raises(psycopg.errors.UniqueViolation):
        snapshot(owner, target, inventory_id=identity, payload={"changed": True})


def test_package_versions_architectures_and_provenance(owner: Connection) -> None:
    snap = snapshot(owner, server(owner))
    for arch, version in [
        ("amd64", "1:3.0.2-0ubuntu1.20"),
        ("i386", "1:3.0.2-0ubuntu1.20"),
        ("amd64", "2:3.0.2~rc1+dfsg-1"),
    ]:
        owner.execute(
            (
                "INSERT INTO "
                "inventory.packages(snapshot_id,name,version,architecture,package_man"
                "ager,software_identity) VALUES (%s,'openssl',%s,%s,'dpkg',%s)"
            ),
            (snap, version, arch, "openssl:" + arch),
        )
    rows = owner.execute(
        "SELECT version,source_package FROM inventory.packages WHERE snapshot_id=%s", (snap,)
    ).fetchall()
    assert (
        len(rows) == 3
        and rows[-1]["version"] == "2:3.0.2~rc1+dfsg-1"
        and (rows[-1]["source_package"] is None)
    )


def test_cve_revisions_source_history_and_current_fk(owner: Connection) -> None:
    identifier, revision = cve(owner)
    other, _ = cve(owner)
    owner.execute(
        (
            "INSERT INTO "
            "cve.enrichments(cve_id,source_id,source_revision,content_sha256,orig"
            "inal_json,observed_at,fixed_version) VALUES "
            "(%s,'ubuntu','1',sha256('revision1'::bytea),'{}',now(),'1:2-ubuntu3'"
            ")"
        ),
        (identifier,),
    )
    owner.execute(
        (
            "INSERT INTO "
            "cve.enrichments(cve_id,source_id,source_revision,content_sha256,orig"
            "inal_json,observed_at,fixed_version) VALUES "
            "(%s,'osv','1',sha256('revision2'::bytea),'{}',now(),'2:3-osv1')"
        ),
        (identifier,),
    )
    owner.execute("UPDATE cve.records SET current_revision_id=%s WHERE id=%s", (revision, other))
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        owner.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_findings_stable_history_archive_and_no_auto_close(owner: Connection) -> None:
    target = server(owner)
    identity = finding(owner, target)
    owner.execute(
        (
            "INSERT INTO findings.status_history(finding_id,new_status,reason) "
            "VALUES (%s,'open','initial evidence')"
        ),
        (identity,),
    )
    snapshot(owner, target, quality="partial")
    owner.execute(
        ("UPDATE inventory.servers SET status='archived',archived_at=now(),version=2 WHERE id=%s"),
        (target,),
    )
    assert (
        required_row(
            owner.execute("SELECT status FROM findings.findings WHERE id=%s", (identity,))
        )["status"]
        == "open"
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        owner.execute(
            "UPDATE findings.findings SET status='unknown',version=2 WHERE id=%s", (identity,)
        )


@pytest.mark.parametrize("username", ["Ａlice", "ALICE", "alice"])
def test_unicode_username_unique(owner: Connection, username: str) -> None:
    user(owner, "Alice")
    with pytest.raises(psycopg.errors.UniqueViolation):
        user(owner, username)


def test_security_grants_not_upload_inheritance(owner: Connection) -> None:
    target = server(owner)
    grouping = group(owner)
    person = user(owner)
    owner.execute(
        ("INSERT INTO inventory.server_group_memberships(server_id,group_id) VALUES (%s,%s)"),
        (target, grouping),
    )
    owner.execute(
        "INSERT INTO security.user_group_access(user_id,group_id) VALUES (%s,%s)",
        (person, grouping),
    )
    row = owner.execute(
        (
            "SELECT can_read,can_upload FROM security.effective_server_access "
            "WHERE user_id=%s AND server_id=%s"
        ),
        (person, target),
    ).fetchone()
    assert row == {"can_read": True, "can_upload": False}
    owner.execute(
        (
            "INSERT INTO "
            "security.user_server_access(user_id,server_id,can_upload) VALUES "
            "(%s,%s,true)"
        ),
        (person, target),
    )
    assert required_row(
        owner.execute(
            (
                "SELECT can_upload FROM security.effective_server_access WHERE "
                "user_id=%s AND server_id=%s"
            ),
            (person, target),
        )
    )["can_upload"]


@pytest.mark.parametrize(
    "table,columns,values",
    [
        ("password_credentials", "user_id,password_hash", "%s,'plaintext'"),
        (
            "sessions",
            ("user_id,verifier,csrf_verifier,auth_version,origin,expires_at,idle_expires_at"),
            ("%s,'short','short',1,'https://example.invalid',now()-interval '1 day',now()"),
        ),
        ("mfa_methods", "user_id,kind,ciphertext,key_id", "%s,'totp','plaintext','external-key-1'"),
        ("recovery_codes", "user_id,verifier", "%s,'plaintext'"),
        (
            "account_tokens",
            "user_id,purpose,verifier,expires_at",
            "%s,'activation',sha256('x'::bytea),now()-interval '1 day'",
        ),
        ("user_server_access", "user_id,server_id", "%s,gen_random_uuid()"),
        ("user_group_access", "user_id,group_id", "%s,gen_random_uuid()"),
        ("user_roles", "user_id,role_id", "%s,gen_random_uuid()"),
    ],
)
def test_security_constraints(owner: Connection, table: str, columns: str, values: str) -> None:
    from psycopg import sql

    person = user(owner)
    with pytest.raises(psycopg.IntegrityError):
        owner.execute(
            sql.SQL("INSERT INTO security.{}({}) VALUES ({})").format(
                sql.Identifier(table), sql.SQL(columns), sql.SQL(values)
            ),
            (person,),
        )


def test_unknown_server_and_original_metadata_rejected(owner: Connection) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        snapshot(owner, uuid.uuid4())


def test_original_payload_must_match_server(owner: Connection) -> None:
    target = server(owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        snapshot(owner, target, payload={"server_id": str(uuid.uuid4())})


def test_original_inventory_hash_cannot_be_changed(owner: Connection) -> None:
    identity = snapshot(owner, server(owner))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        owner.execute(
            ("UPDATE inventory.snapshots SET content_sha256=sha256('changed'::bytea) WHERE id=%s"),
            (identity,),
        )


def test_same_cve_duplicate_and_revision_append_only(owner: Connection) -> None:
    identifier, _ = cve(owner)
    with pytest.raises(psycopg.errors.UniqueViolation):
        cve(owner, identifier)


def test_multiple_installed_versions_are_distinct_matching_evidence(owner: Connection) -> None:
    target = server(owner)
    identity = finding(owner, target)
    owner.execute(
        (
            "INSERT INTO "
            "matching.results(run_id,snapshot_id,server_id,cve_id,cve_revision_id"
            ",component_identity,installation_context,installed_version,status,ru"
            "le_id,source_id,evidence,reason) SELECT "
            "m.run_id,m.snapshot_id,m.server_id,m.cve_id,m.cve_revision_id,m.comp"
            "onent_identity,m.installation_context,'2:3.0-test','fixed',m.rule_id"
            ",m.source_id,m.evidence,m.reason FROM matching.results m JOIN "
            "findings.findings f ON f.current_match_id=m.id WHERE f.id=%s"
        ),
        (identity,),
    )
    assert (
        required_row(
            owner.execute(
                "SELECT count(*) AS n FROM matching.results WHERE server_id=%s", (target,)
            )
        )["n"]
        == 2
    )
