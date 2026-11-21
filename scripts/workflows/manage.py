"""Prepare, install and activate central n8n control without touching vendor images."""

import argparse
import json
import time

from cve_importer.contracts import Configuration
from cve_notification.control import STAGES

from scripts.automation import manage as dispatcher
from scripts.database import manage as db
from scripts.infrastructure.manage import Config, load_config
from scripts.notifications import manage as notification


def prepare(config: Config) -> None:
    notification.prepare(config)
    dispatcher.prepare(config)
    base = dispatcher.directory(config)
    source = notification.directory(config)
    notification.write(
        base / "workflow-webhook.token", (source / "workflow-webhook.key").read_bytes()
    )
    notification.write(base / "workflow-ca.crt", (source / "ca.crt").read_bytes())
    path = base / "targets.json"
    targets = [r for r in json.loads(path.read_text()) if not r["id"].startswith("workflow-")]
    targets.extend(
        {
            "id": "workflow-" + stage,
            "origin": "https://cve-n8n:5678",
            "path": "/webhook/cve-control-platform",
            "token_file": "/run/cve-dispatcher/workflow-webhook.token",
            "ca_file": "/run/cve-dispatcher/workflow-ca.crt",
            "timeout": 5,
        }
        for stage in STAGES
    )
    notification.write(path, json.dumps(targets, indent=2).encode())
    with db.connect(config) as connection:
        for stage in STAGES:
            connection.execute(
                """
INSERT INTO automation.delivery_targets(id,enabled,retry_base,retry_cap)
VALUES(%s,true,1,60) ON CONFLICT(id) DO NOTHING
""",
                ("workflow-" + stage,),
            )
            connection.execute(
                """
INSERT INTO automation.event_routes(event_type,destination)
SELECT code,%s FROM automation.event_types WHERE code LIKE 'workflow.%%.'||%s
ON CONFLICT DO NOTHING
""",
                ("workflow-" + stage, stage),
            )


def install(config: Config) -> None:
    prepare(config)
    notification.install_workflows(config)


def enable(config: Config, *, automatic_updates: bool = True) -> None:
    # Activation is a deliberate last deployment step, after the real workflow runtime is ready.
    with db.connect(config, database="n8n") as connection:
        active = {
            r["id"]
            for r in connection.execute("SELECT id FROM public.workflow_entity WHERE active")
        }
    required = {"cve-control-" + stage for stage in STAGES} | {
        "cve-control-platform",
        "cve-control-queue",
    }
    if not required <= active:
        raise ValueError("Publish and activate all central workflows before enabling control")
    path = config.secrets_base / "cve-importer" / config.project / "sources.json"
    sources = Configuration.model_validate_json(path.read_bytes())
    if (
        "cve_list" not in sources.enabled
        or not set(sources.enabled) <= {"cve_list", "cisa_kev"}
        or sources.cve_list_transport != "git"
    ):
        raise ValueError("Central updates require V5 Git with optional KEV and EPSS risk data")
    with db.connect(config) as connection:
        running = connection.execute("""
SELECT count(*) AS n FROM automation.jobs WHERE runtime_version=1
AND job_type<>'status.collect' AND status IN ('running','queued','retry_pending')
""").fetchone()
        if running and running["n"]:
            raise ValueError("Drain existing application jobs before central-control activation")
        activated = connection.execute(
            """
UPDATE automation.workflow_settings SET enabled=true,auto_updates=%s,
source_config=%s::jsonb,next_update_at=clock_timestamp()+make_interval(secs=>update_interval),
updated_at=clock_timestamp() WHERE singleton RETURNING updated_at
""",
            (automatic_updates, sources.model_dump_json()),
        ).fetchone()
    assert activated
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with db.connect(config) as connection:
            receipt = connection.execute(
                "SELECT 1 FROM automation.workflow_requests WHERE stage='status' "
                "AND released_at >= %s LIMIT 1",
                (activated["updated_at"],),
            ).fetchone()
        if receipt:
            return
        time.sleep(1)
    raise RuntimeError("Central control enabled but no real n8n status approval received")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "install", "enable", "status"])
    parser.add_argument("--manual-updates-only", action="store_true")
    args = parser.parse_args()
    config = load_config()
    if args.action == "prepare":
        prepare(config)
    elif args.action == "install":
        install(config)
    elif args.action == "enable":
        enable(config, automatic_updates=not args.manual_updates_only)
    else:
        with db.connect(config, "reporter") as connection:
            row = connection.execute("SELECT automation.workflow_summary() AS status").fetchone()
            print(json.dumps(row, default=str))


if __name__ == "__main__":
    main()
