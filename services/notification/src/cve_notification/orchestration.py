"""Private reference-only n8n triggers; encrypted n8n credentials carry service headers."""

import hmac
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
from cve_common.config.validation import load_settings
from cve_common.database.engine import Database
from cve_common.database.transactions import transaction
from cve_common.jobs.errors import ErrorCode, JobError

from cve_notification.contracts import Settings
from cve_notification.files import private as read
from cve_notification.repository import one


def runtime(base: Path) -> dict[str, Any]:
    result = json.loads((base / "runtime.json").read_text())
    if set(result) != {"sender", "dashboard", "relay_instance"}:
        raise ValueError("Invalid fixed runtime configuration")
    return result  # type: ignore[no-any-return]


def service_authorized(base: Path, supplied: str) -> bool:
    if not 16 <= len(supplied) <= 256:
        return False
    current = read(base / "service-key.current").decode().strip()
    if hmac.compare_digest(current, supplied):
        return True
    previous = base / "service-key.previous"
    if previous.exists() and datetime.now(UTC).timestamp() - previous.stat().st_mtime <= 3600:
        return hmac.compare_digest(read(previous).decode().strip(), supplied)
    return False


async def trigger(database: Database, identity: UUID | None, base: Path | None = None) -> None:
    if identity is None:
        raise JobError(ErrorCode.INVALID_PAYLOAD)
    base = base or load_settings(Settings).configuration_dir
    async with transaction(database) as s:
        n = await one(
            s,
            (
                "SELECT * FROM automation.notification_intents WHERE id=:id AND st"
                "atus='ready' FOR UPDATE"
            ),
            id=identity,
        )
        if not n:
            return
        run = await one(
            s,
            (
                "SELECT * FROM automation.notification_workflow_runs WHERE notific"
                "ation_id=:id AND state IN ('requested','executing') AND expires_a"
                "t>clock_timestamp() ORDER BY created_at DESC LIMIT 1"
            ),
            id=identity,
        )
        if run is None:
            run = await one(
                s,
                (
                    "INSERT INTO automation.notification_workflow_runs(id,notification"
                    "_id,workflow,workflow_version,request_id,state,expires_at) VALUES"
                    "(:id,:notification,'dispatch',1,:request,'requested',clock_timest"
                    "amp()+interval '5 minutes') RETURNING *"
                ),
                id=uuid4(),
                notification=identity,
                request=uuid4(),
            )
        assert run
    context = ssl.create_default_context(cafile=str(base / "ca.crt"))
    async with httpx.AsyncClient(
        verify=context, timeout=10, trust_env=False, follow_redirects=False
    ) as client:
        response = await client.post(
            "https://cve-n8n:5678/webhook/finding-notification-dispatch",
            headers={"X-CVE-Webhook": read(base / "webhook-key").decode().strip()},
            json={"run_id": str(run["id"]), "request_id": str(run["request_id"])},
        )
        if response.status_code not in {200, 202}:
            raise JobError(ErrorCode.UNAVAILABLE)
