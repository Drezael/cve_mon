"""Saved dashboard settings survive container restarts and replacement, including their keys."""

import asyncio
import hashlib
import json
import secrets
import shutil
import ssl
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from cve_common.smtp_settings import SMTPKeyring
from cve_common.ssh_credentials import SSHKeyring
from cve_notification.contracts import Preferences, Rule, Template
from psycopg import sql

from scripts.database import manage as db
from scripts.deployment.contracts import Environment
from scripts.deployment.orchestration import start_runtime
from scripts.infrastructure import mail
from scripts.infrastructure.manage import Config, compose
from scripts.notifications import manage as notifications
from scripts.smtp.manage import process
from tests.authorization.integration.conftest import actor, fresh
from tests.inventory_upload.integration.conftest import Browser
from tests.orchestration.test_runtime import browser, eventually, platform, upload_lab
from tests.server_administration.integration.conftest import (
    assign_groups,
    create_group,
    create_server,
)

__all__ = ["browser", "platform", "upload_lab"]
pytestmark = pytest.mark.orchestration

TABLES = (
    "security.users",
    "security.password_credentials",
    "security.mfa_methods",
    "security.recovery_codes",
    "security.roles",
    "security.role_permissions",
    "security.user_roles",
    "security.user_server_access",
    "security.user_group_access",
    "inventory.servers",
    "inventory.server_groups",
    "inventory.server_group_memberships",
    "inventory.ansible_profiles",
    "inventory.collection_targets",
    "dashboard.ungrouped_server_order",
    "dashboard.order_versions",
    "dashboard.user_preferences",
    "automation.notification_preferences",
    "automation.notification_rules",
    "automation.notification_templates",
    "automation.smtp_configs",
    "automation.smtp_routes",
    "automation.workflow_settings",
    "findings.policy_versions",
    "findings.active_policy",
    "findings.notes",
    "findings.assignments",
    "findings.reviews",
    "findings.exceptions",
    "findings.exception_decisions",
    "findings.mitigations",
    "status.maintenance_windows",
)


@pytest.fixture(autouse=True)
def cleanup_host_controller(platform: Config) -> Iterator[None]:
    yield
    assert platform.project.startswith("cve-db-test-")
    if shutil.which("systemctl"):
        subprocess.run(
            ["systemctl", "--user", "stop", "cve-automation-control-" + platform.project],
            check=False,
            capture_output=True,
        )


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def snapshot(config: Config) -> dict[str, str]:
    values = {}
    with db.connect(config) as s:
        for name in TABLES:
            schema, table = name.split(".")
            row = s.execute(
                sql.SQL(
                    "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY "
                    "to_jsonb(t)::text),'[]') AS value FROM {}.{} t"
                ).format(sql.Identifier(schema), sql.Identifier(table))
            ).fetchone()
            assert row
            values[name] = digest(row["value"])
    with db.connect(config, database="n8n") as s:
        for table, columns in [
            ("workflow_entity", "id,name,nodes,connections,active,settings"),
            ("credentials_entity", "id,name,type,data"),
        ]:
            rows = s.execute(
                sql.SQL("SELECT " + columns + " FROM {} ORDER BY id").format(sql.Identifier(table))
            ).fetchall()
            values["n8n." + table] = digest(rows)
    return values


def private_files(config: Config) -> dict[str, str]:
    root = config.root / ".runtime"
    paths = [
        root / "services" / config.project / name
        for name in ["auth-keys.json", "ssh-keys.json", "smtp-keys.json", "auth-gateway.key"]
    ]
    paths += [
        notifications.directory(config) / name
        for name in ["runtime.json", "smtp-delivery.json", "smtp-client.crt", "smtp-client.key"]
    ]
    paths += [notifications.n8n_directory(config) / "config/encryption.key"]
    paths += [
        mail.directory(config) / name
        for name in ["state/policy.json", "state/smtp-profiles.json", "secrets/smtp-profiles.json"]
    ]
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


async def test_saved_settings_survive_restart_and_recreation(
    platform: Config, browser: Browser, tmp_path: Path
) -> None:
    assert platform.project.startswith("cve-db-test-")
    person = await actor(browser)
    viewer = await actor(browser, ("viewer",))
    headers = {"cookie": "__Host-cve-session=" + person.cookie, "x-csrf-token": person.csrf}
    server = await create_server(
        browser,
        person,
        display_name="Persistence server",
        description="Preserved description",
        environment="staging",
        criticality="high",
    )
    group = await create_group(browser, person, description="Preserved group")
    membership = await assign_groups(browser, person, server["id"], [group["id"]])
    assert membership.status_code == 200, membership.text
    ssh_password = secrets.token_urlsafe(32)
    ansible = await browser.client.put(
        "/api/v1/dashboard/servers/" + server["id"] + "/ansible",
        headers=headers,
        json={
            "host": "192.0.2.123",
            "port": 2222,
            "username": "collector",
            "auth_method": "password",
            "password": ssh_password,
            "enabled": False,
            "use_sudo": True,
            "interval_seconds": 43200,
            "mount_paths": ["/srv/apps"],
        },
    )
    assert ansible.status_code == 200, ansible.text
    preferences = await browser.client.put(
        "/api/v1/dashboard/notifications/preferences",
        headers={**headers, "If-Match": '"0"'},
        json={
            "preferences": Preferences(
                enabled=False,
                mode="digest",
                digest_hours=168,
                timezone="Europe/Berlin",
                minimum_priority="high",
            ).model_dump(mode="json"),
            "reason": "Persistent preferences test",
        },
    )
    assert preferences.status_code == 200, preferences.text
    fresh(browser, person)
    rules = await browser.client.post(
        "/api/v1/dashboard/notifications/rules",
        headers={**headers, "If-Match": '"0"'},
        json={
            "rule": Rule(enabled=False, minimum_priority="critical", rate_per_hour=7).model_dump(
                mode="json"
            ),
            "reason": "Persistent rule test",
        },
    )
    assert rules.status_code == 200, rules.text
    templates = await browser.client.get(
        "/api/v1/dashboard/notifications/templates", headers=headers
    )
    current = next(r for r in templates.json()["items"] if r["name"] == "finding")
    fresh(browser, person)
    template = Template(
        name="finding", subject="Persistent ${title}", text="${items}", html="<p>${items}</p>"
    )
    changed = await browser.client.post(
        "/api/v1/dashboard/notifications/templates",
        headers={**headers, "If-Match": '"' + str(current["version"]) + '"'},
        json={"template": template.model_dump(), "reason": "Persistent template test"},
    )
    assert changed.status_code == 200, changed.text
    schedule = await browser.client.put(
        "/api/v1/dashboard/orchestration/settings",
        headers=headers,
        json={"auto_updates": False, "update_interval": 43200},
    )
    assert schedule.status_code == 200, schedule.text
    fresh(browser, person)
    starts = datetime.now(UTC) + timedelta(days=2)
    maintenance = await browser.client.post(
        "/api/v1/status/admin/maintenance",
        headers=headers,
        json={
            "service_ids": ["importer"],
            "starts_at": starts.isoformat(),
            "ends_at": (starts + timedelta(hours=2)).isoformat(),
            "description": "Persistent maintenance window",
            "reason": "Persistence test",
        },
    )
    assert maintenance.status_code == 200, maintenance.text
    smtp_password = secrets.token_urlsafe(32)
    smtp_ids = []
    smtp_profiles: list[tuple[str, dict[str, Any]]] = [
        ("administration/smtp", {"enabled": False}),
        ("notifications/mail", {"enabled": True, "mode": "custom"}),
    ]
    for endpoint, extra in smtp_profiles:
        response = await browser.client.put(
            "/api/v1/dashboard/" + endpoint,
            headers={**headers, "Idempotency-Key": str(uuid4())},
            json={
                "version": 0,
                "host": "smtp.persistence.example.test",
                "port": 587,
                "sender": "security@example.test",
                "recipients": ["one@example.test", "two@example.test"],
                "username": "persist-account",
                "password": smtp_password,
                **extra,
            },
        )
        assert response.status_code == 202, response.text
        identity = response.json()["id"]
        smtp_ids.append(identity)
        await asyncio.to_thread(
            eventually,
            platform,
            "SELECT c.state='authorized' AND q.finished_at<clock_timestamp()-interval "
            "'2 seconds' AS ready FROM automation.smtp_configs c JOIN "
            "automation.n8n_queue q ON q.id=c.queue_id WHERE c.id=%s",
            (identity,),
        )
        await asyncio.to_thread(process, platform)
        with db.connect(platform) as s:
            saved = s.execute(
                "SELECT state,error_code FROM automation.smtp_configs WHERE id=%s", (identity,)
            ).fetchone()
            assert saved and saved["state"] == "applied", saved
    with browser.lab.owner() as s:
        s.execute(
            "INSERT INTO "
            "security.user_server_access(user_id,server_id,can_read,can_upload,findings_read,findings_manage)"
            " VALUES(%s,%s,true,true,true,false)",
            (viewer.id, server["id"]),
        )
        s.execute(
            "INSERT INTO dashboard.user_preferences(user_id,preferences) VALUES(%s,%s::jsonb)",
            (viewer.id, json.dumps({"theme": "dark"})),
        )
    origin = browser.service.settings.origin
    context = ssl.create_default_context(cafile=platform.values["TLS_TRUST_FILE"])
    paths = [
        "/api/v1/dashboard/notifications/mail",
        "/api/v1/dashboard/administration/smtp",
        "/api/v1/dashboard/notifications/preferences",
        "/api/v1/dashboard/servers/" + server["id"] + "/ansible",
    ]
    async with httpx.AsyncClient(
        base_url=origin, verify=context, headers={"cookie": headers["cookie"], "origin": origin}
    ) as client:
        expected = {}
        for path in paths:
            result = await client.get(path)
            assert result.status_code == 200, result.text
            expected[path] = result.json()
        # A deliberately disabled workflow and control flag must remain disabled on recovery.
        await asyncio.to_thread(compose, platform, ["stop", "cve-api", "cve-processing", "cve-n8n"])
        with db.connect(platform) as s:
            s.execute("UPDATE automation.workflow_settings SET enabled=false")
            s.execute(
                "UPDATE automation.delivery_targets SET enabled=false WHERE id='workflow-index'"
            )
        with db.connect(platform, database="n8n") as s:
            s.execute(
                "UPDATE workflow_entity SET active=false,name='Persistent customized "
                "index' WHERE id='cve-control-index'"
            )
        before = await asyncio.to_thread(snapshot, platform)
        files_before = private_files(platform)
        postgres_before = compose(platform, ["ps", "-q", "cve-postgres"]).stdout.strip()
        # Docker restart keeps volumes; replacement additionally discards the writable layer.
        await asyncio.to_thread(compose, platform, ["restart", "cve-postgres"])
        await asyncio.to_thread(
            compose, platform, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"]
        )
        assert await asyncio.to_thread(snapshot, platform) == before
        await asyncio.to_thread(
            compose,
            platform,
            ["up", "-d", "--force-recreate", "--wait", "--wait-timeout", "60", "cve-postgres"],
        )
        assert compose(platform, ["ps", "-q", "cve-postgres"]).stdout.strip() != postgres_before
        await asyncio.to_thread(
            compose, platform, ["rm", "-f", "cve-api", "cve-processing", "cve-n8n"]
        )
        target = Environment(tmp_path / "environment.json", {"kind": "staging"}, platform)
        await asyncio.to_thread(start_runtime, target, tmp_path)
        assert await asyncio.to_thread(snapshot, platform) == before
        assert private_files(platform) == files_before
        for path in paths:
            actual = await client.get(path)
            assert actual.status_code == 200, actual.text
            assert actual.json() == expected[path], path
    ring = SMTPKeyring(platform.root / ".runtime/services" / platform.project / "smtp-keys.json")
    with db.connect(platform) as s:
        for identity in smtp_ids:
            saved = s.execute(
                "SELECT * FROM automation.smtp_configs WHERE id=%s", (identity,)
            ).fetchone()
            assert (
                saved
                and ring.decrypt(saved["id"], saved["key_id"], bytes(saved["credentials"]))[
                    "password"
                ]
                == smtp_password
            )
        ssh = s.execute(
            "SELECT * FROM inventory.ansible_profiles WHERE server_id=%s", (server["id"],)
        ).fetchone()
        assert (
            ssh
            and SSHKeyring(
                platform.root / ".runtime/services" / platform.project / "ssh-keys.json"
            ).decrypt(ssh["server_id"], ssh["version"], ssh["key_id"], bytes(ssh["ciphertext"]))[
                "password"
            ]
            == ssh_password
        )
    report = {
        "database_restart": True,
        "database_recreated": True,
        "application_containers_recreated": True,
        "configuration_tables_verified": len(TABLES),
        "n8n_workflows_and_credentials_preserved": True,
        "saved_api_settings_unchanged": len(paths),
        "smtp_and_ssh_credentials_decrypted": True,
        "disabled_flags_preserved": True,
        "live_system_restarted": False,
    }
    (platform.root / ".runtime/test-reports/settings-persistence.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
