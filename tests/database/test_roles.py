"""Tatsächliche TLS-/SCRAM-Logins und negative Rechteprüfungen."""

import json
import uuid
from typing import Any

import psycopg
import pytest

from scripts.database.manage import LOGIN_ROLES, RUNTIME_ROLES, connect, container_id, verify
from scripts.infrastructure.manage import Config, docker_command, run
from tests.database.helpers import required_row

pytestmark = [pytest.mark.database, pytest.mark.security]


@pytest.mark.parametrize("role", LOGIN_ROLES)
def test_real_identity_and_restricted_role(db_config: Config, role: str) -> None:
    with connect(db_config, role, "n8n" if role == "n8n_app" else "cve_monitoring") as connection:
        assert required_row(connection.execute("SELECT current_user AS u"))["u"] == role
        assert required_row(
            connection.execute(
                "SELECT ssl AND version IN ('TLSv1.2','TLSv1.3') AS secure FROM "
                "pg_stat_ssl WHERE pid=pg_backend_pid()"
            )
        )["secure"]
        row = connection.execute(
            "SELECT "
            "rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolin"
            "herit FROM pg_roles WHERE rolname=current_user"
        ).fetchone()
        assert row is not None
        assert not any(row.values())
        if role != "cve_migrator":
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SET ROLE postgres_owner")


@pytest.mark.parametrize(
    ("role", "operation"),
    [
        (role, operation)
        for role in RUNTIME_ROLES
        for operation in (
            "CREATE SCHEMA forbidden",
            "CREATE TEMP TABLE forbidden(id int)",
            "SELECT * FROM security.password_credentials",
            "SELECT * FROM security.mfa_methods",
            "UPDATE inventory.servers SET display_name='forbidden'",
            "UPDATE inventory.server_groups SET sort_order=999",
            "DELETE FROM inventory.server_group_memberships",
        )
        if not (role == "api_security" and operation.startswith("SELECT * FROM security."))
        and not (
            role == "dashboard_admin"
            and operation.startswith(("UPDATE inventory.", "DELETE FROM inventory."))
        )
    ],
)
def test_no_excess_runtime_privileges(db_config: Config, role: str, operation: str) -> None:
    with (
        connect(db_config, role) as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(operation)


@pytest.mark.parametrize("role", ("n8n_app", *RUNTIME_ROLES))
def test_database_connection_isolation(db_config: Config, role: str) -> None:
    with (
        pytest.raises(psycopg.OperationalError),
        connect(db_config, role, "cve_monitoring" if role == "n8n_app" else "n8n"),
    ):
        pytest.fail("cross-database login succeeded")


def test_n8n_only_own_tables(db_config: Config) -> None:
    with connect(db_config, "n8n_app", "n8n") as connection:
        connection.execute("CREATE TABLE public.phase3_probe(id int PRIMARY KEY)")
        connection.execute("INSERT INTO public.phase3_probe VALUES (1)")
        assert required_row(connection.execute("SELECT id FROM public.phase3_probe"))["id"] == 1
        connection.rollback()


def test_status_probe_minimal_and_defaults_deny(db_config: Config) -> None:
    with connect(db_config, "status_probe") as connection:
        assert (
            required_row(connection.execute("SELECT * FROM system.health"))["database_ready"] == 1
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("SELECT * FROM inventory.servers")
    with connect(db_config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        connection.execute("CREATE TABLE inventory.future_probe(id int)")
        connection.execute(
            "CREATE FUNCTION system.future_probe() RETURNS int LANGUAGE sql AS 'SELECT 1'"
        )
        assert not required_row(
            connection.execute(
                "SELECT "
                "has_table_privilege('api_reader','inventory.future_probe','SELECT') "
                "AS allowed"
            )
        )["allowed"]
        assert not required_row(
            connection.execute(
                "SELECT "
                "has_function_privilege('api_reader','system.future_probe()','EXECUTE"
                "') AS allowed"
            )
        )["allowed"]
        connection.rollback()


def test_container_network_volume_and_process(db_config: Config) -> None:
    value = json.loads(run([*docker_command(), "inspect", container_id(db_config)]).stdout)[0]
    assert set(value["NetworkSettings"]["Networks"]) == {db_config.project + "_cve_data"}
    assert not value["HostConfig"]["PortBindings"]
    assert value["HostConfig"]["ReadonlyRootfs"]
    assert not value["HostConfig"]["Privileged"]
    assert value["State"]["Health"]["Status"] == "healthy"
    assert any(
        m["Type"] == "volume" and m["Destination"] == "/var/lib/postgresql" for m in value["Mounts"]
    )
    actual = run(
        [*docker_command(), "exec", container_id(db_config), "cat", "/proc/1/status"]
    ).stdout
    assert "Uid:\t70\t70\t70\t70" in actual
    assert "CapEff:\t0000000000000000" in actual
    assert verify(db_config)["schemas"] == 8


@pytest.mark.parametrize("failure", ["no_tls", "wrong_password", "wrong_ca", "wrong_hostname"])
def test_tls_and_authentication_fail_closed(db_config: Config, failure: str) -> None:
    from scripts.database.manage import address, read_secret, secret_file, workdir

    arguments: dict[str, Any] = {
        "host": "wrong.example.invalid" if failure == "wrong_hostname" else "cve-postgres",
        "hostaddr": address(db_config),
        "port": "5432",
        "dbname": "cve_monitoring",
        "user": "api_reader",
        "password": read_secret(secret_file(db_config, "api_reader")),
        "sslmode": "disable" if failure == "no_tls" else "verify-full",
        "sslrootcert": "/etc/ssl/certs/ca-certificates.crt"
        if failure == "wrong_ca"
        else str(workdir(db_config) / "tls/ca.crt"),
        "connect_timeout": "3",
    }
    if failure == "wrong_password":
        arguments["password"] = uuid.uuid4().hex
    with pytest.raises(psycopg.OperationalError), psycopg.connect(**arguments):
        pytest.fail("unsafe connection accepted")


def test_bounded_upload_authorization_without_token_reads(db_config: Config) -> None:
    import hashlib

    from tests.database.helpers import server

    verifier = hashlib.sha256(uuid.uuid4().bytes).digest()
    certificate = "spiffe://example.invalid/inventory/" + uuid.uuid4().hex
    with connect(db_config, "dashboard_admin") as connection:
        target, other = server(connection), server(connection)
    with connect(db_config, "api_security") as connection:
        principal = required_row(
            connection.execute(
                "INSERT INTO security.technical_principals(name,status,certificate_san) "
                "VALUES (%s,'active',%s) RETURNING id",
                (uuid.uuid4().hex, certificate),
            )
        )["id"]
        token = required_row(
            connection.execute(
                "INSERT INTO security.api_tokens(principal_id,verifier,key_id,expires_at) "
                "VALUES (%s,%s,'external-test-key',now()+interval '1 hour') RETURNING id",
                (principal, verifier),
            )
        )["id"]
        connection.execute(
            "INSERT INTO security.principal_server_access(principal_id,server_id) VALUES (%s,%s)",
            (principal, target),
        )
    with connect(db_config, "api_ingest") as connection:
        query = "SELECT security.authorize_upload(%s,%s,%s) AS principal"
        assert (
            required_row(connection.execute(query, (verifier, target, certificate)))["principal"]
            == principal
        )
        assert (
            required_row(connection.execute(query, (verifier, other, certificate)))["principal"]
            is None
        )
        assert (
            required_row(connection.execute(query, (verifier, target, "wrong-san")))["principal"]
            is None
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("SELECT verifier FROM security.api_tokens")
    with connect(db_config, "api_security") as connection:
        connection.execute("UPDATE security.api_tokens SET revoked_at=now() WHERE id=%s", (token,))
    with connect(db_config, "api_ingest") as connection:
        assert (
            required_row(connection.execute(query, (verifier, target, certificate)))["principal"]
            is None
        )
