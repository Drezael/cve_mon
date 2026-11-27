"""Explicit staged rollout through existing controllers; fixed images, no volume deletion."""

import json
import shutil
import socket
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

from cve_notification.control import STAGES

from scripts.database import manage as db
from scripts.deployment.contracts import Environment, atomic, environment, read
from scripts.deployment.preflight import check
from scripts.deployment.release import verify
from scripts.deployment.state import authorize, journal, lock, transition
from scripts.infrastructure.manage import (
    compose,
    docker_command,
    generate_certificates,
    load_config,
    render,
    run,
)


def stage(path: Path) -> Environment:
    """Provision only a NEW isolated development-PKI staging contract; no service starts."""
    if path.exists():
        raise ValueError("New staging directory required")
    path.mkdir(parents=True, mode=0o700)
    project = "cve-db-test-phase24-" + uuid4().hex[:12]
    cfg = load_config()

    def port() -> str:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return str(sock.getsockname()[1])

    pki = (cfg.root / ".runtime/staging" / project / "pki").resolve()
    values = {
        **cfg.external_values,
        "APP_ENV": "development",
        "COMPOSE_PROJECT_NAME": project,
        "INGRESS_BIND_IP": "127.0.0.1",
        "INGRESS_HTTP_PORT": port(),
        "INGRESS_HTTPS_PORT": port(),
        "TLS_DIR": str(pki),
        "LETSENCRYPT_ENABLED": "false",
    }
    env = path / "platform.env"
    env.write_text("".join(k + "=" + v + "\n" for k, v in sorted(values.items())))
    env.chmod(0o600)
    atomic(
        path / "environment.json",
        {
            "schema_version": 1,
            "name": "stage-" + uuid4().hex[:8],
            "kind": "staging",
            "env_file": "platform.env",
            "minimum_free_bytes": 10 * 1024**3,
            "minimum_available_memory_bytes": 4 * 1024**3,
            "minimum_cpus": 2,
            "certificate_minimum_seconds": 3600,
        },
        exclusive=True,
    )
    return environment(path / "environment.json")


def pinned(target: Environment, bundle: Path) -> Environment:
    manifest = verify(bundle, current_source=True)
    from scripts.deployment.artifacts import local_reference

    overlay = target.control / ("images-" + manifest["release_id"] + ".json")
    value = {"services": {i["service"]: {"image": local_reference(i)} for i in manifest["images"]}}
    if overlay.exists():
        if read(overlay) != value:
            raise ValueError("Different release requires a separate rollout plan")
    else:
        atomic(overlay, value, exclusive=True)
    return replace(target, config=replace(target.config, compose_overrides=(overlay,)))


def prepare(target: Environment, bundle: Path) -> None:
    if target.kind == "production":
        # Only validate operator-provisioned credentials; never generate production secrets.
        check(target, bundle, prepared=True, database_probe=False)
        return
    db.prepare(target.config)
    generate_certificates(target.config)


def prepare_runtime(target: Environment, bundle: Path) -> None:
    from scripts.automation import manage as automation
    from scripts.cve_enricher import manage as enricher
    from scripts.cve_findings import manage as findings
    from scripts.cve_importer import manage as importer
    from scripts.cve_matcher import manage as matcher
    from scripts.infrastructure import mail
    from scripts.inventory_processor import manage as inventory
    from scripts.notifications import manage as notification
    from scripts.services import manage as api

    c = target.config
    from scripts.infrastructure.storage import STORES
    from scripts.infrastructure.storage import prepare as prepare_storage

    prepare_storage(c, list({item[1] for item in STORES.values()}))
    if target.kind != "production":
        # Staging is deliberately quiet even when a new migration enables a
        # default report rule. Append a version, preserving immutable audit data.
        with db.connect(c) as connection:
            connection.execute("""
INSERT INTO automation.notification_rules(rule_key,version,config,reason)
SELECT rule_key,version+1,config||'{"enabled":false}'::jsonb,
 'Isolated staging: notification rules disabled'
FROM (SELECT DISTINCT ON(rule_key) * FROM automation.notification_rules
 ORDER BY rule_key,version DESC) current
WHERE coalesce((config->>'enabled')::boolean,false)
""")
    for module in [
        api,
        automation,
        inventory,
        importer,
        enricher,
        matcher,
        findings,
        mail,
        notification,
    ]:
        module.prepare(c)
    api.prepare(c)
    from scripts.application.manage import prepare as prepare_group

    for group in ("cve-processing", "cve-sources"):
        prepare_group(c, group)
    destination = c.directory / "dashboard"
    shutil.copytree(bundle / "frontend", destination, dirs_exist_ok=True)
    render(c)


def identities(target: Environment, manifest: dict[str, Any]) -> dict[str, Any]:
    c = target.config
    expected = {v["service"]: v for v in manifest["images"]}
    rows = [json.loads(line) for line in compose(c, ["ps", "--format", "json"]).stdout.splitlines()]
    if len(rows) != 7 or {v["Service"] for v in rows} != set(expected):
        raise ValueError("All seven core services must be running")
    for row in rows:
        item = expected[row["Service"]]
        actual = run(
            [*docker_command(), "inspect", "--format", "{{.Image}}", row["ID"]]
        ).stdout.strip()
        if row.get("Health") != "healthy" or actual not in [
            item["image_id"],
            *item["config_digests"],
        ]:
            raise ValueError("Unhealthy or wrong release image: " + row["Service"])
    return {"healthy_services": 7, "all_release_images_running": True}


def smoke(target: Environment, bundle: Path) -> dict[str, Any]:
    manifest = verify(bundle, current_source=True)
    c = target.config
    result = identities(target, manifest)
    result["database"] = db.verify(c)
    host = c.values["DASHBOARD_DOMAIN"]
    port = c.values["INGRESS_HTTPS_PORT"]
    base = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "15",
        "--cacert",
        c.values["TLS_TRUST_FILE"],
        "--resolve",
        f"{host}:{port}:127.0.0.1",
    ]
    statuses = {}
    for path, expected in [
        ("/status", "200"),
        ("/api/v1/status/overview", "401"),
        ("/api/v1/dashboard/security/servers", "401"),
        ("/internal/jobs", "404"),
    ]:
        code = run(
            [
                *base,
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                f"https://{host}:{port}" + path,
            ]
        ).stdout
        if code != expected:
            raise ValueError("HTTPS application smoke failed")
        statuses[path] = code
        time.sleep(0.6)
    from scripts.infrastructure import mail

    if target.kind != "production":
        if read(mail.directory(c) / "state/policy.json")["enabled"]:
            raise ValueError("Real staging SMTP is forbidden")
        with db.connect(c) as connection:
            row = connection.execute(
                "SELECT count(*) n FROM (SELECT DISTINCT ON (rule_key) config "
                "FROM automation.notification_rules ORDER BY rule_key,version DESC) active "
                "WHERE (config->>'enabled')::boolean"
            ).fetchone()
            assert row is not None
            if row["n"]:
                raise ValueError("Staging notification rules must remain disabled")
    return {
        **result,
        "https": statuses,
        "release_id": manifest["release_id"],
        "environment": target.identity,
        "technical_smoke": True,
        "functional_acceptance": False,
    }


def rollout(
    target: Environment,
    bundle: Path,
    *,
    approval: Path | None = None,
    staging_evidence: Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    manifest = verify(bundle, current_source=True)
    authorize(target, manifest, approval, staging_evidence)
    # A dry-run reads existing artifacts only; it never provisions PKI or writes a journal.
    if dry_run:
        return check(target, bundle, prepared=False)
    with lock(target):
        previous = journal(target)
        if (
            previous
            and previous[-1]["state"] == "completed"
            and previous[-1]["release_id"] == manifest["release_id"]
            and previous[-1]["environment"] == target.identity
        ):
            return {**smoke(target, bundle), "idempotent": True}
        transition(target, manifest["release_id"], "planned")
        transition(target, manifest["release_id"], "preflight")
        try:
            containers = compose(target.config, ["ps", "--all", "-q"]).stdout.strip()
            volumes = run(
                [
                    *docker_command(),
                    "volume",
                    "ls",
                    "--quiet",
                    "--filter",
                    "label=com.docker.compose.project=" + target.config.project,
                ]
            ).stdout.strip()
            from scripts.infrastructure.storage import directory as storage_directory

            initial = not (containers or volumes or storage_directory(target.config).exists())
            preflight_result = check(
                target, bundle, prepared=not (initial and target.kind != "production")
            )
            if not initial and preflight_result["migration_current"] is None:
                raise ValueError("Existing deployment requires a reachable verified schema first")
            if preflight_result["migration_current"] is not None:
                from scripts.deployment.recovery import require_verified_backup

                require_verified_backup(target)
        except Exception:
            transition(target, manifest["release_id"], "blocked", "preflight_failed")
            raise
        transition(
            target,
            manifest["release_id"],
            "approved",
            "signed_operator" if target.kind == "production" else "isolated_staging",
        )
        transition(target, manifest["release_id"], "deploying")
        c = target.config
        try:
            compose(c, ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "90", "cve-postgres"])
            db.provision(c)
            db.migrate(c, manifest["migration_target"])
            db.verify(c)
            prepare_runtime(target, bundle)
            check(target, bundle, prepared=True)
            start_runtime(target, bundle)
            transition(target, manifest["release_id"], "verifying")
            result = smoke(target, bundle)
            atomic(target.control / "technical-verification.json", result)
            transition(target, manifest["release_id"], "completed")
            return result
        except Exception:
            current = journal(target)[-1]["state"]
            transition(
                target,
                manifest["release_id"],
                "rollback_required" if current == "verifying" else "recovery_required",
                "rollout_failed",
            )
            raise


def start_runtime(target: Environment, bundle: Path) -> None:
    from scripts.application.manage import start as start_group
    from scripts.infrastructure import mail
    from scripts.notifications import manage as notification
    from scripts.workflows import manage as workflow

    c = target.config
    workflow.prepare(c)
    start_group(c, "cve-sources")
    mail.start(c)
    # Detect first installation before the container bootstraps n8n's own schema.
    with db.connect(c, database="n8n") as connection:
        exists = connection.execute("SELECT to_regclass('public.workflow_entity') AS v").fetchone()
        count = (
            connection.execute("SELECT count(*) n FROM public.workflow_entity").fetchone()
            if exists and exists["v"]
            else None
        )
        first_installation = not count or count["n"] == 0
    compose(
        c, ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "cve-api"], managed=False
    )
    start_group(c, "cve-processing")
    # Every actual container start imports and publishes the current repository definitions.
    compose(c, ["up", "-d", "--no-deps", "--force-recreate", "cve-n8n"], managed=False)
    notification.guard(c)
    compose(
        c,
        [
            "up",
            "-d",
            "--no-deps",
            "--no-recreate",
            "--wait",
            "--wait-timeout",
            "120",
            "cve-api",
            "cve-processing",
            "cve-sources",
            "cve-n8n",
        ],
        managed=False,
    )
    required = {"cve-control-" + stage for stage in STAGES} | {
        "cve-control-platform",
        "cve-control-queue",
        "cve-control-watchdog",
    }
    with db.connect(c, database="n8n") as connection:
        central = connection.execute(
            "SELECT count(*) AS n FROM public.workflow_entity WHERE id=ANY(%s)",
            (sorted(required),),
        ).fetchone()
    if not central or central["n"] != len(required):
        raise ValueError("Container startup did not synchronize all central workflow definitions")
    # Application schedules and pauses survive workflow-definition updates.
    if first_installation:
        workflow.enable(c)
    compose(c, ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "60", "cve-nginx"])
    from scripts.dashboard.manage import activate

    activate(c)


def cleanup_stage(target: Environment) -> None:
    """Remove only explicitly generated Phase-24 laboratory resources with matching labels."""
    if target.kind not in {"staging", "integration"} or not target.config.project.startswith(
        "cve-db-test-phase24-"
    ):
        raise ValueError("Only own disposable Phase-24 stages can be removed")
    from scripts.automation_executor.agent import stop as stop_agent

    c = target.config
    stop_agent(c)
    volumes = run(
        [
            *docker_command(),
            "volume",
            "ls",
            "--filter",
            "label=com.docker.compose.project=" + c.project,
            "--format",
            "{{.Name}}",
        ]
    ).stdout.splitlines()
    for name in volumes:
        owner = run(
            [
                *docker_command(),
                "volume",
                "inspect",
                "--format",
                '{{index .Labels "com.docker.compose.project"}}',
                name,
            ]
        ).stdout.strip()
        if owner != c.project:
            raise ValueError("Foreign volume rejected")
    compose(c, ["down"])
    from scripts.infrastructure.storage import remove as remove_storage

    remove_storage(c)
    for name in volumes:
        run([*docker_command(), "volume", "rm", name])
