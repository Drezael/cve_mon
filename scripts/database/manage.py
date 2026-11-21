"Kontrollierte PostgreSQL-Provisionierung, Migrationen und isolierte Sicherungstests."

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, cast

import psycopg
from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.util.exc import CommandError
from psycopg import sql
from psycopg.rows import dict_row, tuple_row
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

from scripts.infrastructure.manage import Config, compose, docker_command, load_config, run

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROLES = (
    "api_reader",
    "api_ingest",
    "api_security",
    "dashboard_admin",
    "inventory_processor",
    "importer",
    "enricher",
    "matcher",
    "findings_writer",
    "reporter",
    "event_dispatcher",
    "notification",
    "status_probe",
    "dashboard_preferences",
    "workflow_control",
    "ansible_worker",
)
LOGIN_ROLES = ("cve_migrator", *RUNTIME_ROLES, "n8n_app")
OWNERS = ("postgres_owner", "n8n_owner")
DATABASES = ("cve_monitoring", "n8n")


def workdir(config: Config) -> Path:
    "Jedes Compose-Projekt erhält getrennte, ignorierte Secret-/TLS-Dateien."
    return Path(config.values["PG_WORK_DIR"]) / config.project


def secret_file(config: Config, role: str) -> Path:
    return workdir(config) / "secrets" / (role + ".password")


def read_secret(path: Path) -> str:
    """Lese ein geschütztes Credential ausschließlich im Prozessspeicher."""
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 not in {0o400, 0o600}:
        raise ValueError("Secret-Datei fehlt oder ist für andere Benutzer zugänglich")
    value = path.read_text().removesuffix("\n")
    if not 32 <= len(value) <= 256 or any(char in value for char in "\n\r\x00"):
        raise ValueError("Secret-Datei enthält keinen gültigen starken Einzelwert")
    return value


def prepare(config: Config) -> None:
    "Nur ein neues Entwicklungsprojekt initialisieren; bestehende Secrets niemals ersetzen."
    directory = workdir(config)
    secret_dir = directory / "secrets"
    roles = ("postgres_admin", *LOGIN_ROLES)
    if secret_dir.exists() and any(secret_dir.iterdir()):
        for role in roles:
            path = secret_file(config, role)
            if role in {"workflow_control", "ansible_worker"} and not path.exists():
                if not config.manages_credentials:
                    raise ValueError("External workflow control credential required")
                # Schema 40 adds one identity; preserve every pre-existing credential.
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w") as file:
                    file.write(secrets.token_urlsafe(48) + "\n")
            read_secret(path)
        for name in ("server.crt", "server.key", "ca.crt"):
            if not (directory / "tls" / name).is_file():
                raise ValueError(
                    "Bestehende Secretumgebung hat unvollständige TLS-Dateien; manuell prüfen"
                )
        return
    if not config.manages_credentials:
        raise ValueError("Produktion benötigt extern bereitgestellte Secret-/TLS-Dateien")
    secret_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    private = directory / "private"
    private.mkdir(mode=0o700)
    tls = directory / "tls"
    tls.mkdir(mode=0o700)
    for role in roles:
        path = secret_file(config, role)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(secrets.token_urlsafe(48) + "\n")
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-sha256",
            "-days",
            "365",
            "-keyout",
            str(private / "ca.key"),
            "-out",
            str(tls / "ca.crt"),
            "-subj",
            "/CN=CVE Database "
            + ("Development" if config.values["APP_ENV"] == "development" else "Internal")
            + " CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )
    run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-keyout",
            str(tls / "server.key"),
            "-out",
            str(private / "server.csr"),
            "-subj",
            "/CN=cve-postgres",
        ]
    )
    extensions = private / "server.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:cve-postgres,DNS:localhost,IP:127.0.0.1\n"
    )
    run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(private / "server.csr"),
            "-CA",
            str(tls / "ca.crt"),
            "-CAkey",
            str(private / "ca.key"),
            "-CAcreateserial",
            "-out",
            str(tls / "server.crt"),
            "-days",
            "30",
            "-sha256",
            "-extfile",
            str(extensions),
        ]
    )
    for path in (private / "ca.key", tls / "server.key"):
        path.chmod(0o600)
    if config.values["APP_ENV"] == "development":
        (private / "development.json").write_text('{"purpose":"LOCAL DEVELOPMENT ONLY"}\n')


def container_id(config: Config) -> str:
    value = compose(config, ["ps", "-q", "cve-postgres"]).stdout.strip()
    if not value:
        raise ValueError("PostgreSQL läuft für dieses Projekt nicht")
    return value


def address(config: Config) -> str:
    value = json.loads(run([*docker_command(), "inspect", container_id(config)]).stdout)[0]
    return str(value["NetworkSettings"]["Networks"][config.project + "_cve_data"]["IPAddress"])


def connect(
    config: Config,
    role: str = "postgres_admin",
    database: str = "cve_monitoring",
    autocommit: bool = False,
) -> psycopg.Connection[dict[str, Any]]:
    "Kein Hostport: Linux-Operator erreicht die interne IP, TLS-Name bleibt verifiziert."
    return psycopg.connect(
        host="cve-postgres",
        hostaddr=address(config),
        port=5432,
        dbname=database,
        user=role,
        password=read_secret(secret_file(config, role)),
        sslmode="verify-full",
        gssencmode="disable",
        sslrootcert=str(workdir(config) / "tls/ca.crt"),
        connect_timeout=int(config.values["PG_CONNECT_TIMEOUT"]),
        autocommit=autocommit,
        row_factory=dict_row,
    )


def provision(config: Config, rotate: bool = False) -> None:
    "Wiederholbar, ohne regulären Passwortreset; Rotation nur ausdrücklich auswählen."
    with connect(config, database="postgres", autocommit=True) as connection:
        for owner in OWNERS:
            if not connection.execute(
                "SELECT 1 FROM pg_roles WHERE rolname=%s", (owner,)
            ).fetchone():
                connection.execute(
                    sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT").format(sql.Identifier(owner))
                )
        for role in LOGIN_ROLES:
            present = connection.execute(
                ("SELECT rolpassword IS NOT NULL AS has_password FROM pg_authid WHERE rolname=%s"),
                (role,),
            ).fetchone()
            if present is None:
                connection.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                        "NOREPLICATION NOBYPASSRLS"
                    ).format(sql.Identifier(role))
                )
            if present is None or not present["has_password"] or rotate:
                connection.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(read_secret(secret_file(config, role)))
                    )
                )
            connection.execute(
                sql.SQL("ALTER ROLE {} SET search_path TO pg_catalog").format(sql.Identifier(role))
            )
            connection.execute(
                sql.SQL("ALTER ROLE {} SET timezone TO 'UTC'").format(sql.Identifier(role))
            )
            timeout = "120s" if role == "cve_migrator" else "15s"
            connection.execute(
                sql.SQL("ALTER ROLE {} SET statement_timeout TO {}").format(
                    sql.Identifier(role), sql.Literal(timeout)
                )
            )
            connection.execute(
                sql.SQL("ALTER ROLE {} SET lock_timeout TO '5s'").format(sql.Identifier(role))
            )
        connection.execute("GRANT postgres_owner TO cve_migrator WITH INHERIT FALSE, SET TRUE")
        for database, owner in (("cve_monitoring", "postgres_owner"), ("n8n", "n8n_owner")):
            if not connection.execute(
                "SELECT 1 FROM pg_database WHERE datname=%s", (database,)
            ).fetchone():
                connection.execute(
                    sql.SQL(
                        "CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'UTF8' "
                        "LOCALE_PROVIDER builtin BUILTIN_LOCALE 'PG_UNICODE_FAST'"
                    ).format(sql.Identifier(database), sql.Identifier(owner))
                )
            connection.execute(
                sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database))
            )
        for role in ("cve_migrator", *RUNTIME_ROLES):
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE cve_monitoring TO {}").format(
                    sql.Identifier(role)
                )
            )
        connection.execute("GRANT CONNECT ON DATABASE n8n TO n8n_app")
    for database in DATABASES:
        with connect(config, database=database) as connection:
            connection.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            if database == "n8n":
                connection.execute("GRANT USAGE, CREATE ON SCHEMA public TO n8n_app")


def migration_connection(config: Config) -> psycopg.Connection[tuple[Any, ...]]:
    "SQLAlchemy erwartet Tupel; übrige Operator-Abfragen verwenden Dict-Zeilen."
    connection = cast(psycopg.Connection[tuple[Any, ...]], connect(config, "cve_migrator"))
    connection.row_factory = tuple_row
    return connection


def migrate(config: Config, revision: str = "head", script_location: Path | None = None) -> None:
    "Alembic verwaltet ausschließlich cve_monitoring; keine n8n-Migrationen."
    alembic = AlembicConfig(str(config.root / "database/alembic.ini"))
    if script_location:
        alembic.set_main_option("script_location", str(script_location))
    engine = create_engine("postgresql+psycopg://", creator=lambda: migration_connection(config))
    try:
        with engine.connect() as connection:
            alembic.attributes["connection"] = connection
            command.upgrade(alembic, revision)
    finally:
        engine.dispose()


def verify(config: Config) -> dict[str, Any]:
    "Prüfe Cluster, Head und Runtime-Identitäten, ohne Credentialwerte zu melden."
    from alembic.script import ScriptDirectory

    with connect(config) as connection:
        head = connection.execute("SELECT version_num FROM public.alembic_version").fetchone()
        expected = ScriptDirectory.from_config(
            AlembicConfig(str(config.root / "database/alembic.ini"))
        ).get_current_head()
        if not head or head["version_num"] != expected:
            raise ValueError("Migrationsstand stimmt nicht mit Alembic-Head überein")
        schemas = connection.execute(
            ("SELECT schema_name FROM information_schema.schemata WHERE schema_name=ANY(%s)"),
            (
                [
                    "cve",
                    "inventory",
                    "matching",
                    "findings",
                    "security",
                    "automation",
                    "system",
                    "dashboard",
                ],
            ),
        ).fetchall()
        if len(schemas) != 8:
            raise ValueError("Fachschemas fehlen")
    for role in LOGIN_ROLES:
        with connect(config, role, "n8n" if role == "n8n_app" else "cve_monitoring") as connection:
            assert connection.execute("SELECT current_user AS role").fetchone() == {"role": role}
    return {"head": expected, "schemas": 8, "login_roles": len(LOGIN_ROLES)}


def pg_tool(
    config: Config, arguments: list[str], output: Path | None = None, input_file: Path | None = None
) -> None:
    "PostgreSQL-Werkzeuge als lokale OS-Wartungsidentität, ohne Passwortargument/-env."
    command_line = [
        *docker_command(),
        "exec",
        "-i",
        "--user",
        "postgres",
        container_id(config),
        *arguments,
    ]
    with (
        output.open("wb") if output else tempfile.TemporaryFile() as sink,
        input_file.open("rb") if input_file else tempfile.TemporaryFile() as source,
    ):
        result = subprocess.run(
            command_line,
            stdin=source,
            stdout=sink,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
        )
    if result.returncode:
        raise ValueError("PostgreSQL-Werkzeug fehlgeschlagen; Exitstatus " + str(result.returncode))


def fingerprint(config: Config, database: str) -> dict[str, str]:
    "Vergleiche vollständige persistierte Tabelleninhalte statt nur Zeilenzahlen."
    result: dict[str, str] = {}
    with connect(config, database=database) as connection:
        tables = connection.execute(
            "SELECT schemaname,tablename FROM pg_tables WHERE schemaname NOT IN "
            "('pg_catalog','information_schema') ORDER BY 1,2"
        ).fetchall()
        for row in tables:
            query = sql.SQL("SELECT to_jsonb(t) AS data FROM {}.{} AS t").format(
                sql.Identifier(row["schemaname"]), sql.Identifier(row["tablename"])
            )
            values = connection.execute(query).fetchall()
            canonical = sorted(
                json.dumps(value["data"], sort_keys=True, ensure_ascii=False) for value in values
            )
            result[row["schemaname"] + "." + row["tablename"]] = hashlib.sha256(
                "\n".join(canonical).encode()
            ).hexdigest()
    return result


def role_metadata(config: Config) -> list[dict[str, Any]]:
    with connect(config, database="postgres") as connection:
        return connection.execute(
            (
                "SELECT "
                "rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,ro"
                "lreplication,rolbypassrls FROM pg_roles WHERE rolname=ANY(%s) ORDER "
                "BY rolname"
            ),
            ([*LOGIN_ROLES, *OWNERS],),
        ).fetchall()


def role_settings(config: Config) -> dict[str, list[str]]:
    with connect(config, database="postgres") as connection:
        rows = connection.execute(
            "SELECT rolname,COALESCE(rolconfig,ARRAY[]::text[]) AS settings "
            "FROM pg_roles WHERE rolname=ANY(%s) ORDER BY rolname",
            ([*LOGIN_ROLES, *OWNERS],),
        ).fetchall()
        return {row["rolname"]: sorted(row["settings"]) for row in rows}


def restore_role_settings(config: Config, settings: dict[str, list[str]]) -> None:
    allowed = {"search_path", "timezone", "statement_timeout", "lock_timeout", "jit"}
    if set(settings) != {*LOGIN_ROLES, *OWNERS}:
        raise ValueError("Restore role-setting inventory mismatch")
    with connect(config, database="postgres") as connection:
        for role, values in settings.items():
            for setting in values:
                name, separator, value = setting.partition("=")
                if not separator or name.lower() not in allowed:
                    raise ValueError("Unreviewed role setting in backup")
                connection.execute(
                    sql.SQL("ALTER ROLE {} SET {} TO {}").format(
                        sql.Identifier(role), sql.Identifier(name), sql.Literal(value)
                    )
                )
    if role_settings(config) != settings:
        raise ValueError("Restored role settings differ")


def catalog_metadata(config: Config, database: str) -> dict[str, Any]:
    "Struktur, Eigentümer, ACLs und Policies nach einem Restore vergleichen."
    with connect(config, database=database) as connection:
        return {
            "relations": connection.execute(
                "SELECT n.nspname,c.relname,c.relkind,r.rolname AS "
                "owner,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl,aclde"
                "fault(\"char\"(CASE WHEN c.relkind='S' THEN 's' ELSE 'r' "
                "END),c.relowner))::text AS acl FROM pg_class c JOIN pg_namespace n "
                "ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE "
                "n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname "
                "NOT LIKE 'pg_toast%%' ORDER BY 1,2"
            ).fetchall(),
            "schemas": connection.execute(
                "SELECT nspname,pg_get_userbyid(nspowner) AS owner,nspacl::text AS "
                "acl FROM pg_namespace WHERE nspname NOT LIKE 'pg_%%' AND "
                "nspname<>'information_schema' ORDER BY 1"
            ).fetchall(),
            "constraints": connection.execute(
                "SELECT n.nspname,c.relname,k.conname,pg_get_constraintdef(k.oid) AS "
                "definition FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN "
                "('pg_catalog','information_schema') ORDER BY 1,2,3"
            ).fetchall(),
            "indexes": connection.execute(
                "SELECT schemaname,tablename,indexname,indexdef FROM pg_indexes "
                "WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER "
                "BY 1,2,3"
            ).fetchall(),
            "policies": connection.execute(
                "SELECT "
                "schemaname,tablename,policyname,permissive,roles::text,cmd,qual,with"
                "_check FROM pg_policies ORDER BY 1,2,3"
            ).fetchall(),
            "functions": connection.execute(
                "SELECT "
                "n.nspname,p.proname,pg_get_function_identity_arguments(p.oid) AS "
                "args,pg_get_userbyid(p.proowner) AS owner,p.proacl::text AS "
                "acl,pg_get_functiondef(p.oid) AS definition FROM pg_proc p JOIN "
                "pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN "
                "('pg_catalog','information_schema') ORDER BY 1,2,3"
            ).fetchall(),
            "memberships": connection.execute(
                "SELECT pg_get_userbyid(roleid) AS role,pg_get_userbyid(member) AS "
                "member,admin_option,inherit_option,set_option FROM pg_auth_members "
                "WHERE pg_get_userbyid(member)='cve_migrator' ORDER BY 1,2"
            ).fetchall(),
            "default_privileges": connection.execute(
                "SELECT pg_get_userbyid(defaclrole) AS role,"
                "COALESCE(n.nspname,'*') AS schema,defaclobjtype,defaclacl::text AS acl "
                "FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace "
                "ORDER BY 1,2,3"
            ).fetchall(),
            "database": connection.execute(
                "SELECT datname,pg_get_userbyid(datdba) AS owner,datacl::text AS acl "
                "FROM pg_database WHERE datname=current_database()"
            ).fetchall(),
        }


def backup(config: Config, target: Path) -> Path:
    from scripts.automation_executor.agent import exclusive

    with exclusive(config):
        return _backup(config, target)


def _backup(config: Config, target: Path) -> Path:
    "Konsistente logische Einzel-DB-Dumps, Globals ohne Kennwortverifikatoren, Hashmanifest."
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    from scripts.automation_executor.agent import generation, register_backup

    register_backup(config, target)
    for database in DATABASES:
        file = target / (database + ".dump")
        pg_tool(
            config,
            ["pg_dump", "-h", "/var/run/postgresql", "-U", "postgres_admin", "-Fc", "-d", database],
            output=file,
        )
        file.chmod(0o600)
    pg_tool(
        config,
        [
            "pg_dumpall",
            "-h",
            "/var/run/postgresql",
            "-U",
            "postgres_admin",
            "--globals-only",
            "--no-role-passwords",
        ],
        output=target / "globals.sql",
    )
    metadata = {
        "version": 1,
        "postgres_major": 18,
        "erasure_generation": generation(config),
        "project": config.project,
        "roles": role_metadata(config),
        "role_settings": role_settings(config),
        "fingerprints": {db: fingerprint(config, db) for db in DATABASES},
        "catalogs": {db: catalog_metadata(config, db) for db in DATABASES},
        "external_secrets": [
            "PostgreSQL-Rollenpasswörter separat bereitstellen",
            "TOTP-Verschlüsselungsschlüssel",
            "Späterer n8n-Encryption-Key",
        ],
        "configuration": {
            name: (config.root / "infrastructure/postgres" / name).read_text()
            for name in ("postgresql.conf", "pg_hba.conf", "pg_ident.conf")
        },
    }
    (target / "metadata.json").write_text(json.dumps(metadata, indent=2))
    checksums = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in target.iterdir()
    }
    (target / "manifest.json").write_text(json.dumps(checksums, indent=2))
    for path in target.iterdir():
        path.chmod(0o600)
    return target


def cleanup_test(config: Config) -> None:
    "Löschen ausschließlich bei explizit generiertem DB-Testpräfix."
    if not config.project.startswith(("cve-db-test-", "cve-db-restore-")):
        raise ValueError("Keine Datenlöschung außerhalb eigener Testprojekte")
    compose(config, ["down"])
    from scripts.infrastructure.storage import remove

    remove(config)


def restore_test(config: Config, source: Path) -> dict[str, Any]:
    "Restore ausschließlich in neuer isolierter Instanz, niemals in angegebenem Produktivziel."
    from scripts.automation_executor.agent import generation

    metadata = json.loads((source / "metadata.json").read_text())
    if metadata.get("erasure_generation", 0) < generation(config):
        raise ValueError("Backup predates permanent server erasure")
    manifest = json.loads((source / "manifest.json").read_text())
    if set(manifest) != {"cve_monitoring.dump", "n8n.dump", "globals.sql", "metadata.json"}:
        raise ValueError("Unbekannter Sicherungsumfang")
    for name, digest in manifest.items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != digest:
            raise ValueError("Backup-Prüfsumme stimmt nicht")
    metadata = json.loads((source / "metadata.json").read_text())
    if metadata["postgres_major"] != 18:
        raise ValueError("Fremde PostgreSQL-Hauptversion")
    target = Config(
        config.root,
        {**config.values, "COMPOSE_PROJECT_NAME": "cve-db-restore-" + uuid.uuid4().hex[:12]},
    )
    prepare(target)
    try:
        compose(target, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        provision(target)
        for database in DATABASES:
            pg_tool(
                target,
                [
                    "pg_restore",
                    "-h",
                    "/var/run/postgresql",
                    "-U",
                    "postgres_admin",
                    "--exit-on-error",
                    "-d",
                    database,
                ],
                input_file=source / (database + ".dump"),
            )
        if "role_settings" in metadata:
            restore_role_settings(target, metadata["role_settings"])
        if role_metadata(target) != metadata["roles"]:
            raise ValueError("Rollenattribute weichen nach Restore ab")
        for database in DATABASES:
            if fingerprint(target, database) != metadata["fingerprints"][database]:
                raise ValueError("Wiederhergestellte Daten weichen ab")
        for database in DATABASES:
            actual = catalog_metadata(target, database)
            expected = metadata["catalogs"][database]
            from scripts.database.catalog import equivalent

            if not equivalent(database, actual, expected):
                diagnostic = workdir(target) / "catalog-difference.json"
                diagnostic.write_text(
                    json.dumps({"actual": actual, "expected": expected}, indent=2)
                )
                diagnostic.chmod(0o600)
                raise ValueError("Struktur, Eigentümer oder Berechtigungen weichen nach Restore ab")
        return verify(target)
    finally:
        cleanup_test(target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "secrets",
            "up",
            "provision",
            "migrate",
            "verify",
            "backup",
            "restore-test",
            "inspect",
            "down",
        ],
    )
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--rotate", action="store_true")
    parser.add_argument("--backup-dir", type=Path)
    args = parser.parse_args()
    try:
        config = load_config(args.env_file)
        if args.action == "secrets":
            prepare(config)
        elif args.action == "up":
            for role in ("postgres_admin", *LOGIN_ROLES):
                read_secret(secret_file(config, role))
            compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        elif args.action == "provision":
            provision(config, args.rotate)
        elif args.action == "migrate":
            migrate(config)
        elif args.action == "verify":
            print(json.dumps(verify(config)))
        elif args.action == "backup":
            directory = backup(
                config, args.backup_dir or workdir(config) / ("backup-" + uuid.uuid4().hex)
            )
            print(json.dumps({"backup_dir": str(directory)}))
        elif args.action == "restore-test":
            if not args.backup_dir:
                raise ValueError("--backup-dir ist erforderlich")
            restore_test(config, args.backup_dir)
        elif args.action == "down":
            compose(config, ["stop", "cve-postgres"])
        elif args.action == "inspect":
            with connect(config) as connection:
                print(
                    json.dumps(
                        connection.execute(
                            "SELECT version() AS version,current_database() AS database"
                        ).fetchone()
                    )
                )
        print(json.dumps({"action": args.action, "project": config.project, "result": "ok"}))
        return 0
    except (
        OSError,
        ValueError,
        psycopg.Error,
        subprocess.SubprocessError,
        SQLAlchemyError,
        CommandError,
    ) as exc:
        code = exc.sqlstate if isinstance(exc, psycopg.Error) else type(exc).__name__
        print(json.dumps({"action": args.action, "result": "error", "code": code}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
