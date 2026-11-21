"""Private n8n control plane on the existing TLS listener, with a separate database identity."""

import hmac
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from cve_common.config.secrets import read_secret
from cve_common.database.transactions import transaction
from cve_common.jobs.contracts import Payload
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import Field, ValidationError
from sqlalchemy import text

Stage = Literal[
    "import", "inventory", "enrichment", "index", "matching", "findings", "notifications", "status"
]
STAGES = (
    "import",
    "inventory",
    "enrichment",
    "index",
    "matching",
    "findings",
    "notifications",
    "status",
)


class Command(Payload):
    execution_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    workflow_id: str = Field(pattern=r"^cve-control-[a-z]+$", max_length=64)
    limit: int = Field(default=64, ge=1, le=128)


class QueueCommand(Command):
    workflow_id: Literal["cve-control-queue"]
    iteration: int = Field(default=0, ge=0, le=128)
    id: UUID | None = None
    lease_token: UUID | None = None


def authorized(base: Path, path: str, token: str) -> bool:
    parts = path.split("/")
    if len(parts) != 6 or parts[4] not in STAGES or not token or len(token) > 256:
        return False
    try:
        expected = read_secret(base / ("workflow-key." + parts[4])).get_secret_value()
        return hmac.compare_digest(expected, token)
    except (OSError, ValueError):
        return False


def install(app: FastAPI) -> None:
    @app.post("/internal/v1/orchestration/{stage}/{action}")
    async def control(
        stage: Stage,
        action: Literal[
            "dispatch",
            "tick",
            "queue-claim",
            "queue-command",
            "queue-task",
            "queue-result",
            "queue-event",
        ],
        request: Request,
    ) -> Any:
        try:
            command = (
                QueueCommand if action.startswith("queue-") else Command
            ).model_validate_json(await request.body())
        except ValidationError:
            return JSONResponse({"status": "invalid_command"}, status_code=422)
        if action.startswith("queue-"):
            if stage != "import" or not isinstance(command, QueueCommand):
                return JSONResponse({"status": "queue_context_denied"}, status_code=403)
            database = request.app.state.control_database
            if database is None:
                return JSONResponse({"status": "unavailable"}, status_code=503)
            if command.iteration >= 64 and action == "queue-claim":
                return {"kind": "empty"}
            async with transaction(database) as session:
                if action == "queue-claim":
                    await session.execute(
                        text("SELECT automation.n8n_touch(:execution,:workflow)"),
                        {"execution": command.execution_id, "workflow": command.workflow_id},
                    )
                    result = await session.execute(
                        text("SELECT automation.n8n_claim(:execution,:workflow)"),
                        {"execution": command.execution_id, "workflow": command.workflow_id},
                    )
                else:
                    if command.id is None or command.lease_token is None:
                        return JSONResponse({"status": "receipt_required"}, status_code=422)
                    result = await session.execute(
                        text("SELECT automation.n8n_decide(:id,:token,:kind,:execution,:workflow)"),
                        {
                            "id": command.id,
                            "token": command.lease_token,
                            "kind": action.removeprefix("queue-"),
                            "execution": command.execution_id,
                            "workflow": command.workflow_id,
                        },
                    )
                return result.scalar_one()
        if command.workflow_id != "cve-control-" + stage:
            return JSONResponse({"status": "workflow_denied"}, status_code=403)
        database = request.app.state.control_database
        if database is None:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        async with transaction(database) as session:
            if action == "tick":
                if stage not in {"import", "inventory", "status", "findings", "notifications"}:
                    return JSONResponse({"status": "tick_denied"}, status_code=403)
                result = await session.execute(
                    text("SELECT automation.workflow_tick(:stage,:execution,:workflow)"),
                    {
                        "stage": stage,
                        "execution": command.execution_id,
                        "workflow": command.workflow_id,
                    },
                )
            else:
                result = await session.execute(
                    text("SELECT automation.workflow_dispatch(:stage,:execution,:workflow,:limit)"),
                    {
                        "stage": stage,
                        "execution": command.execution_id,
                        "workflow": command.workflow_id,
                        "limit": command.limit,
                    },
                )
            return result.scalar_one()
